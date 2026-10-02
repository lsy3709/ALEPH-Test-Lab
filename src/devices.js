// 기기 주소(/devices/...)와 "등록된 기기에서 접속 중인지" 확인하는 문지기
// 이 라우터 앞에는 requireLogin(비밀번호) → requireMfa(추가 인증)가 먼저 붙어 있다.
//
// 믿는 것: 서버가 낸 일회용 문제에 대한 서명이, 이 계정에 등록된 공개키로 확인되는지(= 그 개인키를 가진 기기인지)
// 믿지 않는 것: 기기 이름, 요청 헤더(User-Agent·X-Device-*), 요청 본문의 기기 번호, 기기가 주장하는 보안 상태
const crypto = require('node:crypto');
const express = require('express');
const { parsePublicKey, verifySignature } = require('./device-keys');
const { regenerateSession, saveSession } = require('./session-utils');

const CHALLENGE_TTL_MS = 2 * 60 * 1000; // 문제는 2분 안에 한 번만
const RECENT_MFA_MS = 5 * 60 * 1000; // 기기 등록은 추가 인증 후 5분 안에만
const DEVICE_TTL_MS = 30 * 24 * 60 * 60 * 1000; // 등록 유효기간 30일
const MAX_ACTIVE_DEVICES = 3; // 계정당 활성 기기 수
const PURPOSES = ['register', 'login'];
const ID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const MAX_NAME = 40;

const fail = (res, status, error, message) => res.status(status).json({ error, message });

// 저장된 상태(active/blocked)와 만료 시각으로 지금 상태를 계산한다
function deviceState(device, now) {
  if (device.status === 'blocked') return 'blocked';
  if (device.expires_at <= now) return 'expired';
  return 'active';
}

const STATE_ERRORS = {
  blocked: ['device_blocked', '차단된 기기입니다. 다른 등록 기기를 쓰거나 새 기기를 등록하세요.'],
  expired: ['device_expired', '기기 등록 기간(30일)이 지났습니다. 추가 인증 후 같은 기기를 다시 등록하세요.'],
};

// 응답용 모양. 공개키·지문은 넣지 않는다. 모의 보안 상태는 "믿지 않음" 표시와 함께 보여 준다.
function toView(device, now, currentId) {
  let reportedPosture = null;
  try {
    reportedPosture = device.reported_posture ? JSON.parse(device.reported_posture) : null;
  } catch {
    reportedPosture = null;
  }
  return {
    id: device.id,
    name: device.name,
    state: deviceState(device, now),
    createdAt: new Date(device.created_at).toISOString(),
    expiresAt: new Date(device.expires_at).toISOString(),
    lastUsedAt: device.last_used_at ? new Date(device.last_used_at).toISOString() : null,
    current: device.id === currentId,
    reportedPosture,
    postureTrusted: false, // 기기가 스스로 주장한 값이라 서버가 확인할 수 없음 → 허용 판단에 쓰지 않음
  };
}

// 문지기: 서버 세션에 "기기 확인 완료"가 있고, 그 기기가 지금도 활성(차단·만료 아님)일 때만 통과.
// 요청마다 기기 상태를 다시 읽으므로, 차단하거나 만료되면 이미 접속 중인 세션도 바로 막힌다.
function requireDevice(db, clock) {
  return (req, res, next) => {
    const deviceId = req.session.deviceId;
    const device = deviceId
      ? db.prepare('SELECT status, expires_at FROM devices WHERE id = ? AND user_id = ?').get(deviceId, req.user.id)
      : undefined;
    if (!device) return fail(res, 403, 'device_required', '등록된 기기로 확인(서명)을 먼저 하세요.');
    const state = deviceState(device, clock.now());
    if (state !== 'active') return fail(res, 403, ...STATE_ERRORS[state]);
    next();
  };
}

// 기기 확인 완료 → 세션 번호를 새로 발급하고(확인 전 쿠키는 무효) 로그인·추가 인증 정보는 이어받는다
async function markDevice(req, deviceId) {
  const { userId, mfaVerified, mfaVerifiedAt } = req.session;
  await regenerateSession(req);
  Object.assign(req.session, { userId, mfaVerified, mfaVerifiedAt, deviceId });
  await saveSession(req);
}

// 세션에 보관한 문제를 꺼내면서 지운다 → 성공하든 실패하든 한 번만 쓸 수 있다
function takeChallenge(req, purpose, now) {
  const challenge = req.session.deviceChallenge;
  delete req.session.deviceChallenge;
  if (!challenge) return ['challenge_missing', '먼저 /devices/challenge 로 문제를 받으세요(문제는 한 번만 쓸 수 있습니다).'];
  if (challenge.purpose !== purpose) return ['challenge_mismatch', `이 요청에는 purpose 가 '${purpose}' 인 문제가 필요합니다.`];
  if (challenge.expiresAt <= now) return ['challenge_expired', '문제가 만료됐습니다(2분). 다시 받으세요.'];
  return [null, challenge.message];
}

// 이름표: 사람이 알아보기 위한 글자일 뿐. 1~40자, 제어 문자 없음.
function readName(raw) {
  if (typeof raw !== 'string') return null;
  const name = raw.trim();
  if (!name || name.length > MAX_NAME || /[\u0000-\u001f\u007f]/.test(name)) return null;
  return name;
}

// 모의 보안 상태: 저장해서 보여 주기만 한다(300자 이하 객체만)
function readPosture(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const text = JSON.stringify(raw);
  return text.length <= 300 ? text : null;
}

function createDevicesRouter({ db, clock }) {
  const router = express.Router();
  const findByKey = (userId, keyId) => db.prepare('SELECT * FROM devices WHERE user_id = ? AND key_id = ?').get(userId, keyId);
  const findById = (userId, id) => db.prepare('SELECT * FROM devices WHERE user_id = ? AND id = ?').get(userId, id);

  // 내 기기 목록(남의 기기는 보이지 않음)
  router.get('/', (req, res) => {
    const now = clock.now();
    const rows = db.prepare('SELECT * FROM devices WHERE user_id = ? ORDER BY created_at, rowid').all(req.user.id);
    res.json({ devices: rows.map((d) => toView(d, now, req.session.deviceId)) });
  });

  // 문제 받기: 무작위 값 + 목적 + 사용자 번호를 묶은 메시지를 이 세션에만 2분 동안 보관한다
  router.post('/challenge', (req, res) => {
    const purpose = req.body?.purpose;
    if (!PURPOSES.includes(purpose)) return fail(res, 400, 'invalid_purpose', "purpose 는 'register' 또는 'login' 이어야 합니다.");
    const now = clock.now();
    const message = `memo-lab:${purpose}:${crypto.randomBytes(32).toString('base64url')}:${req.user.id}`;
    req.session.deviceChallenge = { purpose, message, expiresAt: now + CHALLENGE_TTL_MS };
    res.json({ message, expiresAt: new Date(now + CHALLENGE_TTL_MS).toISOString() });
  });

  // 기기 등록(만료된 기기면 재등록 = 30일 연장): 최근 추가 인증 + 문제 서명으로 "개인키를 가진 기기"임을 증명
  router.post('/', async (req, res) => {
    const now = clock.now();
    const mfaAt = req.session.mfaVerifiedAt;
    if (!(typeof mfaAt === 'number' && now - mfaAt <= RECENT_MFA_MS)) {
      return fail(res, 403, 'recent_mfa_required', '기기 등록은 추가 인증 후 5분 안에만 할 수 있습니다. 인증 앱의 새 코드로 /auth/mfa/verify 를 다시 하세요.');
    }
    const [challengeError, message] = takeChallenge(req, 'register', now);
    if (challengeError) return fail(res, 400, challengeError, message);

    const name = readName(req.body?.name);
    if (!name) return fail(res, 400, 'invalid_device_name', `기기 이름표는 1~${MAX_NAME}자 문자열이어야 합니다.`);
    const parsed = parsePublicKey(req.body?.publicKey);
    if (!parsed) return fail(res, 400, 'invalid_public_key', 'Ed25519 공개키(SPKI, base64url)만 받습니다.');
    if (!verifySignature(parsed.key, message, req.body?.signature)) {
      return fail(res, 401, 'invalid_signature', '서명이 이 공개키의 짝(개인키)으로 만든 것이 아닙니다.');
    }

    const existing = findByKey(req.user.id, parsed.keyId);
    const existingState = existing && deviceState(existing, now);
    if (existingState === 'blocked') {
      return fail(res, 409, 'device_blocked', '차단된 기기 키는 다시 등록할 수 없습니다. 새 기기 폴더(새 키)를 만드세요.');
    }
    if (existingState === 'active') return fail(res, 409, 'device_already_registered', '이미 등록된 기기입니다. /devices/verify 로 확인하세요.');

    const activeCount = db
      .prepare("SELECT COUNT(*) AS n FROM devices WHERE user_id = ? AND status = 'active' AND expires_at > ?")
      .get(req.user.id, now).n;
    if (activeCount >= MAX_ACTIVE_DEVICES) {
      return fail(res, 409, 'device_limit', `기기는 계정당 ${MAX_ACTIVE_DEVICES}대까지입니다. 쓰지 않는 기기를 차단한 뒤 등록하세요.`);
    }

    const posture = readPosture(req.body?.posture);
    let id;
    if (existing) {
      id = existing.id; // 만료된 같은 키 → 새 줄을 만들지 않고 기간만 연장
      db.prepare('UPDATE devices SET name = ?, reported_posture = ?, expires_at = ?, last_used_at = ? WHERE id = ?')
        .run(name, posture, now + DEVICE_TTL_MS, now, id);
    } else {
      id = crypto.randomUUID();
      db.prepare(
        `INSERT INTO devices (id, user_id, name, key_id, public_key, reported_posture, created_at, expires_at, last_used_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      ).run(id, req.user.id, name, parsed.keyId, parsed.publicKey, posture, now, now + DEVICE_TTL_MS, now);
    }
    await markDevice(req, id); // 등록할 때 이미 서명으로 증명했으므로 이 세션은 바로 기기 확인 완료
    const view = toView(findById(req.user.id, id), now, id);
    if (existing) return res.json({ device: view, renewed: true });
    res.status(201).json({ device: view });
  });

  // 기기 확인(로그인할 때마다): 등록된 공개키 + 그 짝인 개인키로 만든 서명 + 활성 상태
  router.post('/verify', async (req, res) => {
    const now = clock.now();
    const [challengeError, message] = takeChallenge(req, 'login', now);
    if (challengeError) return fail(res, 400, challengeError, message);

    const parsed = parsePublicKey(req.body?.publicKey);
    if (!parsed) return fail(res, 400, 'invalid_public_key', 'Ed25519 공개키(SPKI, base64url)만 받습니다.');
    const device = findByKey(req.user.id, parsed.keyId); // 이 계정에 등록된 키만 찾는다(이름·기기 번호로 찾지 않음)
    if (!device) return fail(res, 403, 'device_not_registered', '이 계정에 등록되지 않은 기기입니다.');
    const state = deviceState(device, now);
    if (state !== 'active') return fail(res, 403, ...STATE_ERRORS[state]);
    if (!verifySignature(parsed.key, message, req.body?.signature)) {
      return fail(res, 401, 'invalid_signature', '서명이 이 기기의 개인키로 만든 것이 아닙니다.');
    }

    db.prepare('UPDATE devices SET last_used_at = ? WHERE id = ?').run(now, device.id);
    await markDevice(req, device.id);
    res.json({ device: toView({ ...device, last_used_at: now }, now, device.id) });
  });

  // 차단(분실·도난 신고): 내 기기만. 차단은 되돌리지 않는다 — 다시 쓰려면 새 키로 등록.
  router.post('/:id/block', (req, res) => {
    const now = clock.now();
    const id = ID_PATTERN.test(req.params.id) ? req.params.id : null;
    const device = id && findById(req.user.id, id);
    if (!device) return fail(res, 404, 'device_not_found', '내 기기 중에 그런 기기가 없습니다.');
    if (device.status !== 'blocked') {
      db.prepare("UPDATE devices SET status = 'blocked', blocked_at = ? WHERE id = ?").run(now, id);
    }
    res.json({ device: toView(findById(req.user.id, id), now, req.session.deviceId) });
  });

  return router;
}

module.exports = { createDevicesRouter, requireDevice, deviceState };
