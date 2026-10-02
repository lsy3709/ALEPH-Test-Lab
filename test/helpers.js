// 테스트 공용 도구: 빈 메모리 DB로 서버를 띄우고, 요청을 보내 결과를 돌려준다
const { openDb } = require('../src/db');
const { createApp } = require('../src/app');

// 실제 data/app.db 는 건드리지 않는다. 테스트가 끝나면 메모리 DB는 사라진다.
async function startTestServer() {
  const db = openDb(':memory:');
  const app = createApp({ db });
  const server = await new Promise((resolve) => {
    const s = app.listen(0, '127.0.0.1', () => resolve(s)); // 0 = 비어 있는 아무 포트
  });
  const baseUrl = `http://127.0.0.1:${server.address().port}`;
  const close = () => new Promise((resolve) => server.close(resolve));
  return { db, baseUrl, close };
}

// body 가 문자열이면 그대로(깨진 JSON 시험용), 객체면 JSON 으로 바꿔 보낸다.
async function request(baseUrl, method, path, body) {
  const hasBody = body !== undefined;
  const res = await fetch(baseUrl + path, {
    method,
    headers: hasBody ? { 'content-type': 'application/json' } : {},
    body: hasBody ? (typeof body === 'string' ? body : JSON.stringify(body)) : undefined,
  });
  const text = await res.text();
  let json = null;
  try {
    json = text ? JSON.parse(text) : null;
  } catch {
    json = null;
  }
  return { status: res.status, json };
}

module.exports = { startTestServer, request };
