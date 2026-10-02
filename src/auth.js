// 계정 관련 주소(/auth/...): 2단계는 가입만
const express = require('express');
const { checkPasswordPolicy, hashPassword } = require('./passwords');

const SQLITE_CONSTRAINT_UNIQUE = 2067; // SQLite 오류 번호: UNIQUE(중복 금지) 규칙 위반
const MAX_EMAIL = 254;
const EMAIL_PATTERN = /^[a-z0-9._%+-]+@[a-z0-9-]+(\.[a-z0-9-]+)+$/;

// 실습용 안전장치(보안 통제가 아님): 진짜 개인정보가 들어오지 않도록
// 인터넷 표준(RFC 2606)이 예시용으로 남겨 둔 도메인만 받는다.
const PRACTICE_DOMAINS = ['example.com', 'example.net', 'example.org'];
const PRACTICE_SUFFIXES = ['.test', '.example', '.invalid', '.localhost'];

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

function createAuthRouter({ db }) {
  const router = express.Router();

  // 가입: 이메일·비밀번호 검사 → 비밀번호 해시 → 사용자 저장
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

  return router;
}

module.exports = { createAuthRouter };
