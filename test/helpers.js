// 테스트 공용 도구: 빈 메모리 DB로 서버를 띄우고, 요청을 보내고, 쿠키를 기억하는 클라이언트를 만든다
const { openDb } = require('../src/db');
const { createApp } = require('../src/app');

// 테스트 전용 가짜 값(실제 .env 의 비밀키나 실제 비밀번호가 아님)
const TEST_SESSION_SECRET = 'test-only-session-secret-0123456789abcdef';
const FAKE_PASSWORD = 'lab-only-Pass-2026';
const SESSION_COOKIE = 'memo.sid';

// 실제 data/app.db 는 건드리지 않는다. 테스트가 끝나면 메모리 DB는 사라진다.
// options 로 로그인 시도 제한 등을 바꿀 수 있다(기본은 일반 검사가 제한에 걸리지 않게 넉넉히).
async function startTestServer(options = {}) {
  const db = openDb(':memory:');
  const app = createApp({ db, sessionSecret: TEST_SESSION_SECRET, loginRateLimit: { limit: 1000 }, ...options });
  const server = await new Promise((resolve, reject) => {
    const s = app.listen(0, '127.0.0.1', (err) => (err ? reject(err) : resolve(s))); // 0 = 비어 있는 아무 포트
  });
  const baseUrl = `http://127.0.0.1:${server.address().port}`;
  const close = () => new Promise((resolve) => server.close(resolve));
  return { db, baseUrl, close };
}

// body 가 문자열이면 그대로(깨진 JSON 시험용), 객체면 JSON 으로 바꿔 보낸다.
// headers 로 쿠키 등을 직접 넣을 수 있다(위조 쿠키 시험용).
async function request(baseUrl, method, path, body, headers = {}) {
  const hasBody = body !== undefined;
  const res = await fetch(baseUrl + path, {
    method,
    headers: { ...(hasBody ? { 'content-type': 'application/json' } : {}), ...headers },
    body: hasBody ? (typeof body === 'string' ? body : JSON.stringify(body)) : undefined,
  });
  const text = await res.text();
  let json = null;
  try {
    json = text ? JSON.parse(text) : null;
  } catch {
    json = null;
  }
  return { status: res.status, json, setCookies: res.headers.getSetCookie() };
}

// 브라우저처럼 쿠키를 기억했다가 다음 요청에 자동으로 붙이는 클라이언트
function createClient(baseUrl) {
  const jar = new Map();

  async function send(method, path, body, headers = {}) {
    const cookie = [...jar].map(([name, value]) => `${name}=${value}`).join('; ');
    const res = await request(baseUrl, method, path, body, { ...(cookie ? { cookie } : {}), ...headers });
    for (const line of res.setCookies) {
      const [pair, ...attrs] = line.split(';');
      const eq = pair.indexOf('=');
      const name = pair.slice(0, eq).trim();
      const value = pair.slice(eq + 1).trim();
      const expires = attrs.find((a) => /^\s*expires=/i.test(a));
      const expired = expires && new Date(expires.split('=')[1]) <= new Date();
      if (!value || expired) jar.delete(name);
      else jar.set(name, value);
    }
    return res;
  }

  return { send, cookie: (name) => jar.get(name) };
}

// 가입만 하기
async function signup(baseUrl, email, password = FAKE_PASSWORD) {
  const res = await request(baseUrl, 'POST', '/auth/signup', { email, password });
  if (res.status !== 201) throw new Error(`가입 실패(${res.status}): ${email}`);
  return res.json.user;
}

// 로그인한 클라이언트 만들기
async function login(baseUrl, email, password = FAKE_PASSWORD) {
  const client = createClient(baseUrl);
  const res = await client.send('POST', '/auth/login', { email, password });
  if (res.status !== 200) throw new Error(`로그인 실패(${res.status}): ${email}`);
  return client;
}

// 쿠키 값(s%3A<세션번호>.<서명>)에서 세션 번호만 꺼낸다 — 서버 세션 표와 대조할 때 쓴다
function sessionIdFromCookie(cookieValue) {
  const raw = decodeURIComponent(cookieValue);
  return raw.slice(2, raw.lastIndexOf('.'));
}

module.exports = {
  TEST_SESSION_SECRET,
  FAKE_PASSWORD,
  SESSION_COOKIE,
  startTestServer,
  request,
  createClient,
  signup,
  login,
  sessionIdFromCookie,
};
