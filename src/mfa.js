// 추가 인증 주소(/auth/mfa/...)와 "추가 인증까지 마쳤는지" 확인하는 문지기
// 이 라우터 앞에는 requireLogin(비밀번호 로그인 확인)이 먼저 붙어 있어 req.user 가 들어 있다.
const express = require('express');
const { newSecret, otpauthUrl, checkCode } = require('./totp');
const { regenerateSession, saveSession } = require('./session-utils');

const INVALID_CODE = { error: 'invalid_code', message: '코드가 틀렸거나 이미 사용한 코드입니다.' };
const LOCKED = { error: 'mfa_locked', message: '추가 인증 실패가 너무 많아 잠시 잠겼습니다. 15분 뒤 다시 시도하세요.' };

const getUser = (db, id) =>
  db
    .prepare('SELECT id, email, totp_secret, totp_enabled, totp_last_step, totp_failures, totp_locked_until FROM users WHERE id = ?')
    .get(id);

// 추가 인증 통과 → 세션 번호를 새로 발급하고(인증 전 쿠키는 무효) "추가 인증 완료" 표시를 서버 세션에 남긴다
async function markVerified(req, userId, nowMs) {
  await regenerateSession(req);
  req.session.userId = userId;
  req.session.mfaVerified = true;
  req.session.mfaVerifiedAt = nowMs; // 다음 미션(기기 등록)에서 "방금 인증했는지" 확인에 쓴다
  await saveSession(req);
}

// 문지기: 서버 세션에 추가 인증 완료 표시가 있고, 계정에 추가 인증이 등록돼 있을 때만 통과.
// 요청 본문·헤더·주소에 무엇이 적혀 있든 보지 않는다.
function requireMfa(db) {
  return (req, res, next) => {
    const user = db.prepare('SELECT totp_enabled FROM users WHERE id = ?').get(req.user.id);
    if (!user?.totp_enabled) {
      return res.status(403).json({ error: 'mfa_setup_required', message: '추가 인증(인증 앱)을 먼저 등록하세요.' });
    }
    if (req.session.mfaVerified !== true) {
      return res.status(403).json({ error: 'mfa_required', message: '인증 앱의 6자리 코드를 먼저 입력하세요.' });
    }
    next();
  };
}

// clock: 지금 시각을 알려 주는 함수 묶음(서버는 진짜 시각, 테스트는 가짜 시계)
// lock: 연속 실패 maxFailures 번이면 lockMs 동안 잠금
function createMfaRouter({ db, clock, lock: { maxFailures = 5, lockMs = 15 * 60 * 1000 } = {} }) {
  const router = express.Router();

  // 비밀값이 오가는 응답은 브라우저·프록시가 저장하지 않게 한다
  router.use((req, res, next) => {
    res.set('Cache-Control', 'no-store');
    next();
  });

  // 등록 시작: 새 비밀값을 만들어 "이 세션에만" 임시 보관하고 사용자에게 한 번 보여 준다
  router.post('/setup', (req, res) => {
    const user = getUser(db, req.user.id);
    if (user.totp_enabled) {
      // 비밀번호만 아는 사람이 자기 인증 앱으로 바꿔치기하지 못하게 막는다
      return res.status(409).json({
        error: 'mfa_already_enabled',
        message: '이미 추가 인증이 등록되어 있습니다. 휴대폰을 잃어버렸다면 관리자 초기화가 필요합니다.',
      });
    }
    const secret = newSecret();
    req.session.pendingTotpSecret = secret;
    res.json({
      secret,
      otpauthUrl: otpauthUrl(secret, user.email),
      message: '인증 앱에 이 설정 키를 등록한 뒤, 앱에 뜬 6자리 코드를 /auth/mfa/enable 로 보내세요. 키는 다시 보여 주지 않습니다.',
    });
  });

  // 등록 완료: 인증 앱이 만든 코드가 맞으면 그때 계정에 비밀값을 저장한다
  router.post('/enable', async (req, res) => {
    const now = clock.now();
    const user = getUser(db, req.user.id);
    if (user.totp_enabled) return res.status(409).json({ error: 'mfa_already_enabled', message: '이미 등록되어 있습니다.' });

    const secret = req.session.pendingTotpSecret;
    if (!secret) {
      return res.status(400).json({ error: 'mfa_setup_not_started', message: '먼저 /auth/mfa/setup 으로 등록을 시작하세요.' });
    }
    const step = checkCode(secret, req.body?.code, now);
    if (step === null) return res.status(401).json(INVALID_CODE);

    db.prepare(
      `UPDATE users SET totp_secret = ?, totp_enabled = 1, totp_last_step = ?, totp_failures = 0, totp_locked_until = NULL
       WHERE id = ? AND totp_enabled = 0`,
    ).run(secret, step, user.id);
    await markVerified(req, user.id, now); // 임시 비밀값은 세션 교체와 함께 사라진다
    res.json({ mfa: 'enabled' });
  });

  // 로그인 때 확인: 맞는 코드 + 처음 쓰는 코드 + 잠금 아님 → 추가 인증 완료
  router.post('/verify', async (req, res) => {
    const now = clock.now();
    const user = getUser(db, req.user.id);
    if (!user.totp_enabled) {
      return res.status(409).json({ error: 'mfa_not_enabled', message: '추가 인증이 아직 등록되지 않았습니다. /auth/mfa/setup 부터 하세요.' });
    }
    if (user.totp_locked_until && user.totp_locked_until > now) return res.status(429).json(LOCKED);

    const step = checkCode(user.totp_secret, req.body?.code, now);
    // 재사용 방지: 이미 통과한 30초 칸 이하의 코드는 거부. 조건이 맞을 때만 바뀌도록 UPDATE 하나로 처리한다.
    const accepted =
      step !== null &&
      db
        .prepare(
          `UPDATE users SET totp_last_step = ?, totp_failures = 0, totp_locked_until = NULL
           WHERE id = ? AND (totp_last_step IS NULL OR totp_last_step < ?)`,
        )
        .run(step, user.id, step).changes === 1;

    if (!accepted) {
      const failures = user.totp_failures + 1;
      if (failures >= maxFailures) {
        db.prepare('UPDATE users SET totp_failures = 0, totp_locked_until = ? WHERE id = ?').run(now + lockMs, user.id);
        return res.status(429).json(LOCKED);
      }
      db.prepare('UPDATE users SET totp_failures = ? WHERE id = ?').run(failures, user.id);
      return res.status(401).json(INVALID_CODE);
    }

    await markVerified(req, user.id, now);
    res.json({ mfa: 'verified' });
  });

  return router;
}

module.exports = { createMfaRouter, requireMfa };
