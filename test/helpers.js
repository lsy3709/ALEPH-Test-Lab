// 테스트 공용 도구: 빈 메모리 DB로 서버를 띄우고, 요청을 보내고, 쿠키를 기억하는 클라이언트를 만든다
const OTPAuth = require('otpauth');
const { openDb } = require('../src/db');
const { createApp } = require('../src/app');

// 테스트 전용 가짜 값(실제 .env 의 비밀키나 실제 비밀번호가 아님)
const TEST_SESSION_SECRET = 'test-only-session-secret-0123456789abcdef';
const FAKE_PASSWORD = 'lab-only-Pass-2026';
const SESSION_COOKIE = 'memo.sid';

// 테스트 전용 가짜 시계: 30초 단위로 바뀌는 TOTP 코드를 기다리지 않고 시험하려고 시간을 직접 움직인다.
// 실제 서버(server.js)는 이 시계를 쓰지 않고 진짜 시각(Date.now)을 쓴다.
function createFakeClock(start = Date.UTC(2026, 9, 2, 0, 0, 0)) {
  let now = start;
  return { now: () => now, advance: (ms) => (now += ms) };
}

// 실제 data/app.db 는 건드리지 않는다. 테스트가 끝나면 메모리 DB는 사라진다.
// options 로 로그인 시도 제한 등을 바꿀 수 있다(기본은 일반 검사가 제한에 걸리지 않게 넉넉히).
async function startTestServer(options = {}) {
  const db = openDb(':memory:');
  const clock = createFakeClock();
  const app = createApp({ db, sessionSecret: TEST_SESSION_SECRET, loginRateLimit: { limit: 1000 }, clock, ...options });
  const server = await new Promise((resolve, reject) => {
    const s = app.listen(0, '127.0.0.1', (err) => (err ? reject(err) : resolve(s))); // 0 = 비어 있는 아무 포트
  });
  const baseUrl = `http://127.0.0.1:${server.address().port}`;
  const close = () => new Promise((resolve) => server.close(resolve));
  // authenticatorApp: 휴대폰 인증 앱 흉내 — 등록할 때 받은 비밀값을 이메일별로 기억한다
  return { db, baseUrl, close, clock, authenticatorApp: new Map() };
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
  return { status: res.status, json, headers: res.headers, setCookies: res.headers.getSetCookie() };
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

// 비밀번호 로그인만 한 클라이언트(추가 인증 전)
async function login(baseUrl, email, password = FAKE_PASSWORD) {
  const client = createClient(baseUrl);
  const res = await client.send('POST', '/auth/login', { email, password });
  if (res.status !== 200) throw new Error(`로그인 실패(${res.status}): ${email}`);
  return client;
}

// 인증 앱 흉내: 비밀값과 시각으로 6자리 코드를 계산한다(휴대폰 앱이 하는 일과 같음)
function totpCode(secret, nowMs) {
  const totp = new OTPAuth.TOTP({ secret: OTPAuth.Secret.fromBase32(secret), algorithm: 'SHA1', digits: 6, period: 30 });
  return totp.generate({ timestamp: nowMs });
}

// 인증 앱에 등록: setup 으로 비밀값을 받아 앱(authenticatorApp)에 저장하고, 첫 코드로 enable
async function enrollMfa(srv, client, email) {
  const setup = await client.send('POST', '/auth/mfa/setup');
  if (setup.status !== 200) throw new Error(`추가 인증 등록 시작 실패(${setup.status}): ${email}`);
  srv.authenticatorApp.set(email, setup.json.secret);
  const done = await client.send('POST', '/auth/mfa/enable', { code: totpCode(setup.json.secret, srv.clock.now()) });
  if (done.status !== 200) throw new Error(`추가 인증 등록 완료 실패(${done.status}): ${email}`);
  return done;
}

// 지금 시각의 코드로 추가 인증 확인
function verifyMfa(srv, client, email) {
  return client.send('POST', '/auth/mfa/verify', { code: totpCode(srv.authenticatorApp.get(email), srv.clock.now()) });
}

// 로그인 + 추가 인증까지 마친 클라이언트. 처음이면 인증 앱 등록, 이미 등록됐으면 코드 확인.
async function loginWithMfa(srv, email, password = FAKE_PASSWORD) {
  const client = createClient(srv.baseUrl);
  const res = await client.send('POST', '/auth/login', { email, password });
  if (res.status !== 200) throw new Error(`로그인 실패(${res.status}): ${email}`);
  srv.clock.advance(30_000); // 바로 전에 쓴 코드를 다시 쓰지 않도록 다음 30초 칸으로
  if (res.json.mfa === 'setup_required') {
    await enrollMfa(srv, client, email);
  } else {
    const done = await verifyMfa(srv, client, email);
    if (done.status !== 200) throw new Error(`추가 인증 실패(${done.status}): ${email}`);
  }
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
  createFakeClock,
  startTestServer,
  request,
  createClient,
  signup,
  login,
  totpCode,
  enrollMfa,
  verifyMfa,
  loginWithMfa,
  sessionIdFromCookie,
};
