// 계정 관련 주소(/auth/...): 가입(2단계), 로그인·로그아웃·내 정보(3단계)와 로그인 확인 문지기
const express = require('express');
const rateLimit = require('express-rate-limit');
const { checkPasswordPolicy, hashPassword, verifyPassword } = require('./passwords');
const { regenerateSession, saveSession } = require('./session-utils');

const SQLITE_CONSTRAINT_UNIQUE = 2067; // SQLite 오류 번호: UNIQUE(중복 금지) 규칙 위반
const MAX_EMAIL = 254;
const EMAIL_PATTERN = /^[a-z0-9._%+-]+@[a-z0-9-]+(\.[a-z0-9-]+)+$/;

// 실습용 안전장치(보안 통제가 아님): 진짜 개인정보가 들어오지 않도록
// 인터넷 표준(RFC 2606)이 예시용으로 남겨 둔 도메인만 받는다.
const PRACTICE_DOMAINS = ['example.com', 'example.net', 'example.org'];
const PRACTICE_SUFFIXES = ['.test', '.example', '.invalid', '.localhost'];

// 없는 계정으로 로그인할 때도 진짜 계정과 비슷한 시간이 걸리게 하는 비교용 해시(누구의 비밀번호도 아님).
// 응답 속도 차이로 "이 이메일이 가입돼 있는지" 알아내는 것을 막는다.
const dummyHash = hashPassword('timing-equalizer-not-a-real-password');

const INVALID_LOGIN = { error: 'invalid_credentials', message: '이메일 또는 비밀번호가 올바르지 않습니다.' };

// 앞뒤 공백 제거 + 소문자로 맞춤. 형식이 틀리면 null.
function normalizeEmail(raw) {
  if (typeof raw !== 'string') return null;
  const email = raw.trim().toLowerCase();
  if (email.length > MAX_EMAIL || !EMAIL_PATTERN.test(email)) return null;
  return email;
}

function isPracticeEmail(email) {
  const domain = email.split('@')[1];
  return PRACTICE_DOMAINS.includes(domain) || PRACTICE_SUFFIXES.some((suffix) => domain.endsWith(suffix));
}

// 문지기: 서버에 저장된 세션에 userId 가 있고 그 계정이 아직 있을 때만 통과시킨다.
// 화면이나 요청 본문이 아니라 "서버 세션"만 믿는다.
function requireLogin(db) {
  return (req, res, next) => {
    const userId = req.session?.userId;
    const user = userId ? db.prepare('SELECT id, email FROM users WHERE id = ?').get(userId) : undefined;
    if (!user) return res.status(401).json({ error: 'login_required', message: '로그인이 필요합니다.' });
    req.user = user;
    next();
  };
}

// 로그인 시도 제한: 같은 접속 주소(IP)에서 실패가 limit 번을 넘으면 windowMs 동안 429
function createLoginLimiter({ limit = 10, windowMs = 15 * 60 * 1000 } = {}) {
  return rateLimit({
    windowMs,
    limit,
    skipSuccessfulRequests: true, // 성공한 로그인은 세지 않는다
    standardHeaders: 'draft-8',
    legacyHeaders: false,
    // 이 서버는 프록시 뒤에 있지 않으므로 X-Forwarded-For 같은 헤더를 믿지 않고 실제 접속 주소로만 센다
    validate: { xForwardedForHeader: false },
    handler: (req, res) =>
      res.status(429).json({ error: 'too_many_attempts', message: '로그인 시도가 너무 많습니다. 잠시 후 다시 시도하세요.' }),
  });
}

function createAuthRouter({ db, cookieName, loginRateLimit }) {
  const router = express.Router();

  // 가입: 이메일·비밀번호 검사 → 비밀번호 해시 → 사용자 저장 (로그인은 따로)
  router.post('/signup', async (req, res) => {
    const email = normalizeEmail(req.body?.email);
    if (!email) {
      return res.status(400).json({ error: 'invalid_email', message: '이메일 형식이 올바르지 않습니다.' });
    }
    if (!isPracticeEmail(email)) {
      return res.status(400).json({
        error: 'practice_email_only',
        message: '실습용 가짜 이메일만 쓸 수 있습니다. 예: student1@example.test',
      });
    }

    const problem = checkPasswordPolicy(req.body?.password, email);
    if (problem) return res.status(400).json({ error: 'weak_password', message: problem });

    const passwordHash = await hashPassword(req.body.password);
    try {
      const result = db.prepare('INSERT INTO users (email, password_hash) VALUES (?, ?)').run(email, passwordHash);
      const user = db.prepare('SELECT id, email, created_at AS createdAt FROM users WHERE id = ?').get(result.lastInsertRowid);
      res.status(201).json({ user }); // 응답에는 해시를 넣지 않는다
    } catch (err) {
      if (err.errcode === SQLITE_CONSTRAINT_UNIQUE) {
        return res.status(409).json({ error: 'email_taken', message: '이미 가입된 이메일입니다.' });
      }
      throw err;
    }
  });

  // 로그인: 비밀번호 확인 → 세션 번호를 새로 발급(세션 고정 방지) → 세션에 userId 저장
  // 비밀번호만 통과한 상태이므로 mfaVerified = false. 다음 할 일(등록/확인)을 mfa 로 알려 준다.
  router.post('/login', createLoginLimiter(loginRateLimit), async (req, res) => {
    const email = normalizeEmail(req.body?.email);
    const password = typeof req.body?.password === 'string' ? req.body.password : '';
    const user = email
      ? db.prepare('SELECT id, email, password_hash, totp_enabled FROM users WHERE email = ?').get(email)
      : undefined;

    const passwordOk = await verifyPassword(user ? user.password_hash : await dummyHash, password);
    if (!user || !passwordOk) return res.status(401).json(INVALID_LOGIN); // 어느 쪽이 틀렸는지 알려 주지 않는다

    await regenerateSession(req);
    req.session.userId = user.id;
    req.session.mfaVerified = false;
    await saveSession(req);
    res.json({
      user: { id: user.id, email: user.email },
      mfa: user.totp_enabled ? 'verify_required' : 'setup_required',
    });
  });

  // 로그아웃: 서버 세션을 지우고, 브라우저에도 쿠키를 지우라고 알린다
  router.post('/logout', (req, res, next) => {
    req.session.destroy((err) => {
      if (err) return next(err);
      res.clearCookie(cookieName, { path: '/', httpOnly: true, sameSite: 'strict' });
      res.status(204).end();
    });
  });

  // 내 정보: 서버가 이 요청을 누구의 로그인으로, 어느 인증 단계까지로 보고 있는지 확인하는 용도
  // (추가 인증 비밀값은 절대 넣지 않는다)
  router.get('/me', requireLogin(db), (req, res) => {
    const { totp_enabled: enabled } = db.prepare('SELECT totp_enabled FROM users WHERE id = ?').get(req.user.id);
    res.json({ user: req.user, mfa: { enabled: enabled === 1, verified: req.session.mfaVerified === true } });
  });

  return router;
}

module.exports = { createAuthRouter, requireLogin };
