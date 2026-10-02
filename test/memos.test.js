// 1단계 검사(3·4단계에서 갱신): 메모 기능은 "로그인 + 추가 인증을 마친 주인"에게 예전과 똑같이 동작해야 한다.
// 3단계부터 로그인, 4단계부터 추가 인증이 필요하므로 같은 검사를 그 상태의 클라이언트로 실행한다.
// (로그인·추가 인증 없이 보낸 요청이 거부되는지는 session.test.js·mfa.test.js 에서 따로 검사)
const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { startTestServer, request, signup, loginWithMfa } = require('./helpers');

let srv;
let owner;
before(async () => {
  srv = await startTestServer();
  await signup(srv.baseUrl, 'memo-owner@example.test');
  owner = await loginWithMfa(srv, 'memo-owner@example.test');
});
after(async () => {
  await srv.close();
});

const call = (method, path, body) => owner.send(method, path, body);

test('서버 상태 확인: GET /health → 200 (로그인 없이도 가능)', async () => {
  const res = await request(srv.baseUrl, 'GET', '/health');
  assert.equal(res.status, 200);
  assert.deepEqual(res.json, { ok: true });
});

test('메모 만들기 → 목록·하나 읽기 → 지우기 → 지운 뒤 404', async () => {
  const created = await call('POST', '/memos', { title: '장보기', body: '가짜 메모: 우유, 달걀' });
  assert.equal(created.status, 201);
  assert.equal(created.json.memo.title, '장보기');
  const id = created.json.memo.id;

  const list = await call('GET', '/memos');
  assert.equal(list.status, 200);
  assert.ok(list.json.memos.some((m) => m.id === id));

  const one = await call('GET', `/memos/${id}`);
  assert.equal(one.status, 200);
  assert.equal(one.json.memo.body, '가짜 메모: 우유, 달걀');

  const removed = await call('DELETE', `/memos/${id}`);
  assert.equal(removed.status, 204);

  const after = await call('GET', `/memos/${id}`);
  assert.equal(after.status, 404);
});

test('제목이 없거나 너무 길면 400', async () => {
  assert.equal((await call('POST', '/memos', { body: '제목 없음' })).status, 400);
  assert.equal((await call('POST', '/memos', { title: '   ' })).status, 400);
  assert.equal((await call('POST', '/memos', { title: 'a'.repeat(101) })).status, 400);
  assert.equal((await call('POST', '/memos', { title: '숫자 본문', body: 123 })).status, 400);
});

test('깨진 JSON 은 400 이고 서버 내부 정보를 드러내지 않는다', async () => {
  const res = await call('POST', '/memos', '{"title": 깨짐');
  assert.equal(res.status, 400);
  assert.deepEqual(res.json, { error: 'bad_request' });
});

test('숫자가 아닌 id, 없는 id, 없는 주소는 404', async () => {
  assert.equal((await call('GET', '/memos/abc')).status, 404);
  assert.equal((await call('GET', '/memos/1%20OR%201=1')).status, 404);
  assert.equal((await call('GET', '/memos/999999')).status, 404);
  assert.equal((await call('DELETE', '/memos/999999')).status, 404);
  assert.equal((await call('GET', '/no-such-path')).status, 404);
});
