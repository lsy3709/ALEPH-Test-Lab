// 2단계 검사: 가입과 안전한 비밀번호 저장
const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { startTestServer, request } = require('./helpers');

// 테스트 전용 가짜 비밀번호(어떤 실제 서비스에서도 쓰지 않는 값)
const FAKE_PASSWORD = 'lab-only-Pass-2026';

let srv;
before(async () => {
  srv = await startTestServer();
});
after(async () => {
  await srv.close();
});

const signup = (email, password) => request(srv.baseUrl, 'POST', '/auth/signup', { email, password });
const hashOf = (email) => srv.db.prepare('SELECT password_hash FROM users WHERE email = ?').get(email).password_hash;

test('정상 가입 → 201, 응답에 비밀번호·해시가 없다', async () => {
  const res = await signup('student1@example.test', FAKE_PASSWORD);
  assert.equal(res.status, 201);
  assert.equal(res.json.user.email, 'student1@example.test');
  assert.ok(Number.isInteger(res.json.user.id));

  const text = JSON.stringify(res.json);
  assert.ok(!text.includes(FAKE_PASSWORD), '응답에 비밀번호 원문이 있으면 안 됨');
  assert.ok(!text.includes('$argon2'), '응답에 해시가 있으면 안 됨');
});

test('DB에는 비밀번호 원문 대신 Argon2id 해시만 저장된다', async () => {
  await signup('hash-check@example.test', FAKE_PASSWORD);
  const row = srv.db.prepare('SELECT * FROM users WHERE email = ?').get('hash-check@example.test');
  assert.match(row.password_hash, /^\$argon2id\$v=19\$m=19456,t=2,p=1\$/);
  assert.ok(!Object.values(row).some((v) => String(v).includes(FAKE_PASSWORD)), 'DB 어느 칸에도 원문이 없어야 함');
});

test('같은 비밀번호라도 사용자마다 해시가 다르다(솔트)', async () => {
  await signup('salt-a@example.test', FAKE_PASSWORD);
  await signup('salt-b@example.test', FAKE_PASSWORD);
  assert.notEqual(hashOf('salt-a@example.test'), hashOf('salt-b@example.test'));
});

test('같은 이메일로 다시 가입하면 409 (대소문자·앞뒤 공백이 달라도)', async () => {
  assert.equal((await signup('dup@example.test', FAKE_PASSWORD)).status, 201);
  const again = await signup('  DUP@Example.TEST ', FAKE_PASSWORD);
  assert.equal(again.status, 409);
  assert.equal(again.json.error, 'email_taken');
});

test('약한 비밀번호는 400', async () => {
  const cases = [
    'short', // 너무 짧음
    'a'.repeat(129), // 너무 긺
    'password123', // 흔한 비밀번호
    'my-weak-user-pass', // 이메일 아이디(weak-user)가 들어 있음
    12345678901, // 문자열이 아님
    undefined, // 비밀번호 없음
  ];
  for (const password of cases) {
    const res = await signup('weak-user@example.test', password);
    assert.equal(res.status, 400, `${String(password).slice(0, 20)} 는 거부되어야 함`);
    assert.equal(res.json.error, 'weak_password');
  }
});

test('이메일 형식이 틀리면 400', async () => {
  for (const email of ['not-an-email', 'a@b', '', 123, undefined, `${'a'.repeat(250)}@example.test`]) {
    const res = await signup(email, FAKE_PASSWORD);
    assert.equal(res.status, 400, `${String(email).slice(0, 20)} 는 거부되어야 함`);
    assert.equal(res.json.error, 'invalid_email');
  }
});

test('실습용 안전장치: 실제 서비스 도메인 이메일은 400', async () => {
  const res = await signup('someone@gmail.com', FAKE_PASSWORD);
  assert.equal(res.status, 400);
  assert.equal(res.json.error, 'practice_email_only');
});
