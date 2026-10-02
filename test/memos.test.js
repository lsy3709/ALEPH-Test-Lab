// 1단계 검사: 메모 API 기본 동작
const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { startTestServer, request } = require('./helpers');

let srv;
before(async () => {
  srv = await startTestServer();
});
after(async () => {
  await srv.close();
});

const call = (method, path, body) => request(srv.baseUrl, method, path, body);

test('서버 상태 확인: GET /health → 200', async () => {
  const res = await call('GET', '/health');
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
