// 3단계 검사: 로그인·로그아웃·서버 세션과 메모 보호
const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { openDb } = require('../src/db');
const { createApp } = require('../src/app');
const {
  FAKE_PASSWORD,
  SESSION_COOKIE,
  startTestServer,
  request,
  createClient,
  signup,
  login,
  loginWithMfa,
  sessionIdFromCookie,
} = require('./helpers');

const WRONG_PASSWORD = 'lab-only-Pass-WRONG';

let srv;
before(async () => {
  srv = await startTestServer();
  await signup(srv.baseUrl, 'owner@example.test');
  await signup(srv.baseUrl, 'other@example.test');
});
after(async () => {
  await srv.close();
});

const sessionCount = () => srv.db.prepare('SELECT COUNT(*) AS n FROM sessions').get().n;
const sessionExists = (sid) => Boolean(srv.db.prepare('SELECT 1 FROM sessions WHERE sid = ?').get(sid));
const anonymous = (method, path, body, headers) => request(srv.baseUrl, method, path, body, headers);

test('로그인 성공 → 200, 서버 세션 표에 세션이 실제로 생기고 쿠키는 HttpOnly·SameSite=Strict', async () => {
  const before = sessionCount();
  const client = createClient(srv.baseUrl);
  const res = await client.send('POST', '/auth/login', { email: 'owner@example.test', password: FAKE_PASSWORD });

  assert.equal(res.status, 200);
  assert.equal(res.json.user.email, 'owner@example.test');
  assert.ok(!JSON.stringify(res.json).includes('$argon2'), '응답에 해시가 있으면 안 됨');

  const setCookie = res.setCookies.find((c) => c.startsWith(`${SESSION_COOKIE}=`));
  assert.ok(setCookie, '세션 쿠키가 와야 함');
  assert.match(setCookie, /HttpOnly/i, '자바스크립트가 쿠키를 읽지 못하게');
  assert.match(setCookie, /SameSite=Strict/i, '다른 사이트에서 보낸 요청에는 쿠키가 붙지 않게');

  const sid = sessionIdFromCookie(client.cookie(SESSION_COOKIE));
  assert.equal(sessionCount(), before + 1, '서버 쪽 세션 저장소에 1개 늘어야 함');
  assert.ok(sessionExists(sid), '쿠키의 세션 번호가 서버 표에 있어야 함');

  const me = await client.send('GET', '/auth/me');
  assert.equal(me.status, 200);
  assert.equal(me.json.user.email, 'owner@example.test');
});

test('로그인 전 요청은 세션을 만들지 않는다', async () => {
  const before = sessionCount();
  const health = await anonymous('GET', '/health');
  const memos = await anonymous('GET', '/memos');
  assert.equal(health.setCookies.length, 0);
  assert.equal(memos.setCookies.length, 0);
  assert.equal(sessionCount(), before);
});

test('틀린 비밀번호·없는 계정 → 둘 다 401 같은 응답, 쿠키·세션이 생기지 않음', async () => {
  const before = sessionCount();
  const wrong = await anonymous('POST', '/auth/login', { email: 'owner@example.test', password: WRONG_PASSWORD });
  const nobody = await anonymous('POST', '/auth/login', { email: 'nobody@example.test', password: FAKE_PASSWORD });

  for (const res of [wrong, nobody]) {
    assert.equal(res.status, 401);
    assert.equal(res.json.error, 'invalid_credentials');
    assert.equal(res.setCookies.length, 0);
  }
  assert.deepEqual(wrong.json, nobody.json, '계정이 있는지 없는지 응답으로 구분되면 안 됨');
  assert.equal(sessionCount(), before);

  // 형식이 이상한 입력도 서버 오류(500)가 아니라 401
  assert.equal((await anonymous('POST', '/auth/login', { email: 123, password: ['x'] })).status, 401);
  assert.equal((await anonymous('POST', '/auth/login')).status, 401);
});

test('로그인 없이 메모 API → 401 (목록·만들기·읽기·지우기·내 정보 모두)', async () => {
  const cases = [
    ['GET', '/memos'],
    ['POST', '/memos', { title: '무단 메모' }],
    ['GET', '/memos/1'],
    ['DELETE', '/memos/1'],
    ['GET', '/auth/me'],
  ];
  for (const [method, path, body] of cases) {
    const res = await anonymous(method, path, body);
    assert.equal(res.status, 401, `${method} ${path}`);
    assert.equal(res.json.error, 'login_required');
  }
  const count = srv.db.prepare("SELECT COUNT(*) AS n FROM memos WHERE title = '무단 메모'").get().n;
  assert.equal(count, 0, '로그인 없이 만든 메모가 저장되면 안 됨');
});

test('남의 메모는 읽기·지우기 모두 404, 목록에도 보이지 않는다 (주소의 id 바꾸기 우회 차단)', async () => {
  // 4단계부터 메모는 추가 인증까지 마쳐야 쓸 수 있으므로 두 사람 모두 그 상태로 시험한다
  const owner = await loginWithMfa(srv, 'owner@example.test');
  const other = await loginWithMfa(srv, 'other@example.test');
  const created = await owner.send('POST', '/memos', { title: '주인 메모', body: '가짜 데이터' });
  const id = created.json.memo.id;

  assert.equal((await other.send('GET', `/memos/${id}`)).status, 404);
  assert.equal((await other.send('DELETE', `/memos/${id}`)).status, 404);
  const otherList = await other.send('GET', '/memos');
  assert.ok(!otherList.json.memos.some((m) => m.id === id));

  const stillThere = await owner.send('GET', `/memos/${id}`);
  assert.equal(stillThere.status, 200, '남이 지우려 해도 주인 메모는 그대로');
});

test('로그아웃 → 204, 서버 세션 삭제, 예전 쿠키를 다시 보내도 401 (회수한 자격 재사용 거부)', async () => {
  const client = await login(srv.baseUrl, 'owner@example.test');
  const oldCookie = client.cookie(SESSION_COOKIE);
  const sid = sessionIdFromCookie(oldCookie);
  assert.ok(sessionExists(sid));

  const out = await client.send('POST', '/auth/logout');
  assert.equal(out.status, 204);
  assert.equal(client.cookie(SESSION_COOKIE), undefined, '브라우저 쪽 쿠키도 지우라고 알려야 함');
  assert.ok(!sessionExists(sid), '서버 세션이 남아 있으면 안 됨');

  // 공격자가 로그아웃 전에 쿠키를 복사해 두었다가 다시 보내는 경우
  const replayHeaders = { cookie: `${SESSION_COOKIE}=${oldCookie}` };
  assert.equal((await anonymous('GET', '/memos', undefined, replayHeaders)).status, 401);
  assert.equal((await anonymous('GET', '/auth/me', undefined, replayHeaders)).status, 401);
  assert.equal((await anonymous('POST', '/memos', { title: '재사용' }, replayHeaders)).status, 401);
});

test('위조·변조한 쿠키 → 401', async () => {
  const client = await login(srv.baseUrl, 'owner@example.test');
  const real = client.cookie(SESSION_COOKIE);
  const lastChar = real.at(-1);
  const tampered = real.slice(0, -1) + (lastChar === 'A' ? 'B' : 'A'); // 서명 마지막 글자 하나만 바꿈

  for (const value of ['s%3Afake-session-id.fake-signature', 'not-signed-at-all', tampered]) {
    const res = await anonymous('GET', '/memos', undefined, { cookie: `${SESSION_COOKIE}=${value}` });
    assert.equal(res.status, 401, value);
  }
});

test('로그인할 때마다 세션 번호가 새로 바뀌고 이전 번호는 무효 (세션 고정 공격 방지)', async () => {
  const client = await login(srv.baseUrl, 'owner@example.test');
  const first = client.cookie(SESSION_COOKIE);
  const again = await client.send('POST', '/auth/login', { email: 'owner@example.test', password: FAKE_PASSWORD });
  assert.equal(again.status, 200);
  const second = client.cookie(SESSION_COOKIE);

  assert.notEqual(sessionIdFromCookie(first), sessionIdFromCookie(second));
  const old = await anonymous('GET', '/auth/me', undefined, { cookie: `${SESSION_COOKIE}=${first}` });
  assert.equal(old.status, 401);
});

test('서버에서 만료된 세션은 쿠키가 있어도 401 이고 저장소에서 지워진다', async () => {
  const client = await login(srv.baseUrl, 'owner@example.test');
  const sid = sessionIdFromCookie(client.cookie(SESSION_COOKIE));
  srv.db.prepare('UPDATE sessions SET expires_at = ? WHERE sid = ?').run(Date.now() - 1000, sid);

  assert.equal((await client.send('GET', '/memos')).status, 401);
  assert.ok(!sessionExists(sid));
});

test('계정이 삭제되면 남아 있던 세션도 통하지 않는다', async () => {
  await signup(srv.baseUrl, 'to-delete@example.test');
  const client = await login(srv.baseUrl, 'to-delete@example.test');
  srv.db.prepare('DELETE FROM users WHERE email = ?').run('to-delete@example.test');
  assert.equal((await client.send('GET', '/memos')).status, 401);
});

test('JSON 이 아닌 형식(text/plain)으로 몰래 보낸 메모는 저장되지 않는다 (다른 사이트 위조 요청 대비)', async () => {
  const client = await loginWithMfa(srv, 'owner@example.test');
  const res = await client.send('POST', '/memos', '{"title":"몰래 만든 메모"}', { 'content-type': 'text/plain' });
  assert.equal(res.status, 400);
  const count = srv.db.prepare("SELECT COUNT(*) AS n FROM memos WHERE title = '몰래 만든 메모'").get().n;
  assert.equal(count, 0);
});

test('로그인 실패가 너무 많으면 429, X-Forwarded-For 로 IP를 속여도 우회 불가', async () => {
  const limited = await startTestServer({ loginRateLimit: { limit: 3, windowMs: 60_000 } });
  try {
    await signup(limited.baseUrl, 'rate@example.test');
    const attempt = (password, headers) =>
      request(limited.baseUrl, 'POST', '/auth/login', { email: 'rate@example.test', password }, headers);

    for (let i = 0; i < 3; i++) assert.equal((await attempt(WRONG_PASSWORD)).status, 401);
    assert.equal((await attempt(WRONG_PASSWORD)).status, 429);
    assert.equal((await attempt(WRONG_PASSWORD, { 'x-forwarded-for': '203.0.113.7' })).status, 429);
    // 제한 중에는 맞는 비밀번호도 막는다(공격자가 맞혔는지 확인할 수 없게)
    assert.equal((await attempt(FAKE_PASSWORD)).status, 429);
  } finally {
    await limited.close();
  }
});

test('성공한 로그인은 실패 횟수에 세지 않는다', async () => {
  const limited = await startTestServer({ loginRateLimit: { limit: 3, windowMs: 60_000 } });
  try {
    await signup(limited.baseUrl, 'regular@example.test');
    for (let i = 0; i < 5; i++) {
      const res = await request(limited.baseUrl, 'POST', '/auth/login', { email: 'regular@example.test', password: FAKE_PASSWORD });
      assert.equal(res.status, 200, `${i + 1}번째 정상 로그인`);
    }
  } finally {
    await limited.close();
  }
});

test('세션 비밀키가 없거나 32자보다 짧으면 앱이 시작되지 않는다', () => {
  const db = openDb(':memory:');
  assert.throws(() => createApp({ db }), /SESSION_SECRET/);
  assert.throws(() => createApp({ db, sessionSecret: 'too-short' }), /SESSION_SECRET/);
  db.close();
});
