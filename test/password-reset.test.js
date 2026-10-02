// 관리자 도구 검사: 비밀번호 재설정(npm run password-reset)
const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { FAKE_PASSWORD, startTestServer, request, signup, loginWithMfa } = require('./helpers');
const { resetPassword } = require('../scripts/password-reset');

const NEW_PASSWORD = 'lab-only-NewPass-2026'; // 테스트 전용 가짜 새 비밀번호

let srv;
before(async () => {
  srv = await startTestServer();
});
after(async () => {
  await srv.close();
});

const hashOf = (email) => srv.db.prepare('SELECT password_hash FROM users WHERE email = ?').get(email).password_hash;
const loginAs = (email, password) => request(srv.baseUrl, 'POST', '/auth/login', { email, password });

test('재설정 후에는 새 비밀번호로만 로그인되고, 그 계정의 세션은 모두 끊기며, 다른 계정과 추가 인증 등록은 그대로', async () => {
  await signup(srv.baseUrl, 'reset-me@example.test');
  await signup(srv.baseUrl, 'bystander@example.test');
  const mine = await loginWithMfa(srv, 'reset-me@example.test');
  const theirs = await loginWithMfa(srv, 'bystander@example.test');
  await mine.send('POST', '/memos', { title: '재설정 전 메모', body: '가짜 데이터' });

  const result = await resetPassword(srv.db, 'reset-me@example.test', NEW_PASSWORD);
  assert.equal(result.sessionsRevoked, 1);

  assert.equal((await mine.send('GET', '/memos')).status, 401, '재설정 전 로그인 세션은 회수');
  assert.equal((await theirs.send('GET', '/memos')).status, 200, '다른 계정 세션은 그대로');

  assert.equal((await loginAs('reset-me@example.test', FAKE_PASSWORD)).status, 401, '옛 비밀번호 거부');
  const fresh = await loginAs('reset-me@example.test', NEW_PASSWORD);
  assert.equal(fresh.status, 200);
  assert.equal(fresh.json.mfa, 'verify_required', '추가 인증 등록은 풀리지 않음');

  const again = await loginWithMfa(srv, 'reset-me@example.test', NEW_PASSWORD);
  const memos = await again.send('GET', '/memos');
  assert.deepEqual(memos.json.memos.map((m) => m.title), ['재설정 전 메모'], '메모 데이터 보존');

  assert.match(hashOf('reset-me@example.test'), /^\$argon2id\$/);
  assert.ok(!hashOf('reset-me@example.test').includes(NEW_PASSWORD));
});

test('약한 비밀번호·지금과 같은 비밀번호·없는 계정은 거부하고 아무것도 바꾸지 않는다', async () => {
  await signup(srv.baseUrl, 'keep@example.test');
  const before = hashOf('keep@example.test');

  await assert.rejects(resetPassword(srv.db, 'keep@example.test', 'short'), /10~128자/);
  await assert.rejects(resetPassword(srv.db, 'keep@example.test', 'password123'), /흔한/);
  await assert.rejects(resetPassword(srv.db, 'keep@example.test', 'keep-my-pass-01'), /이메일 아이디/);
  await assert.rejects(resetPassword(srv.db, 'keep@example.test', FAKE_PASSWORD), /같습니다/);
  await assert.rejects(resetPassword(srv.db, 'nobody@example.test', NEW_PASSWORD), /없는 계정/);

  assert.equal(hashOf('keep@example.test'), before);
  assert.equal((await loginAs('keep@example.test', FAKE_PASSWORD)).status, 200);
});
