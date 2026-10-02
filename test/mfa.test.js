// 4단계 검사: 추가 인증(TOTP) 등록·확인과 보호 API
const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const {
  FAKE_PASSWORD,
  SESSION_COOKIE,
  startTestServer,
  request,
  createClient,
  signup,
  login,
  totpCode,
  verifyMfa,
  loginWithMfa,
} = require('./helpers');
const { resetMfa } = require('../scripts/mfa-reset');

let srv;
before(async () => {
  srv = await startTestServer();
});
after(async () => {
  await srv.close();
});

// 5단계부터 메모는 "기기 확인"까지 필요하므로, 이 파일에서 "추가 인증까지 마쳤는지"를 확인하는 주소로는
// 추가 인증까지만 요구하는 /devices(내 기기 목록)를 쓴다. 추가 인증 전 메모 403 검사는 그대로 /memos 로 한다.
const MFA_PROTECTED = '/devices';

const userRow = (email) => srv.db.prepare('SELECT * FROM users WHERE email = ?').get(email);
const replay = (cookieValue, path = MFA_PROTECTED) =>
  request(srv.baseUrl, 'GET', path, undefined, { cookie: `${SESSION_COOKIE}=${cookieValue}` });

// 가입 + 인증 앱 등록까지 끝낸 뒤 로그아웃한 계정을 만든다
async function enrolledAccount(email) {
  await signup(srv.baseUrl, email);
  const client = await loginWithMfa(srv, email);
  await client.send('POST', '/auth/logout');
}

test('로그인만 하고 추가 인증 0회 → 메모 API 403 (등록 전: mfa_setup_required)', async () => {
  // (참고) 메모 주소의 문지기 순서: 로그인 → 추가 인증 → 기기 확인. 여기서는 두 번째 문지기에서 걸린다.
  await signup(srv.baseUrl, 'no-mfa@example.test');
  const client = createClient(srv.baseUrl);
  const res = await client.send('POST', '/auth/login', { email: 'no-mfa@example.test', password: FAKE_PASSWORD });
  assert.equal(res.status, 200);
  assert.equal(res.json.mfa, 'setup_required');

  for (const [method, path, body] of [['GET', '/memos'], ['POST', '/memos', { title: '무단' }], ['GET', '/memos/1'], ['DELETE', '/memos/1']]) {
    const r = await client.send(method, path, body);
    assert.equal(r.status, 403, `${method} ${path}`);
    assert.equal(r.json.error, 'mfa_setup_required');
  }
});

test('인증 앱 등록: 비밀값은 등록할 때 한 번만 주고, 틀린 코드로는 등록되지 않으며, 맞는 코드로 등록하면 추가 인증이 필요한 주소 사용 가능', async () => {
  await signup(srv.baseUrl, 'enroll@example.test');
  const client = await login(srv.baseUrl, 'enroll@example.test');

  const setup = await client.send('POST', '/auth/mfa/setup');
  assert.equal(setup.status, 200);
  assert.match(setup.json.secret, /^[A-Z2-7]{32}$/, '무작위 20바이트 비밀값(base32 32자)');
  assert.ok(setup.json.otpauthUrl.startsWith('otpauth://totp/MemoLab:'));
  assert.equal(setup.headers.get('cache-control'), 'no-store', '비밀값 응답은 저장(캐시)하지 않게');
  assert.equal(userRow('enroll@example.test').totp_enabled, 0, '코드 확인 전에는 아직 등록 아님');

  srv.clock.advance(30_000);
  const right = totpCode(setup.json.secret, srv.clock.now());
  const wrong = right === '000000' ? '000001' : '000000';
  const bad = await client.send('POST', '/auth/mfa/enable', { code: wrong });
  assert.equal(bad.status, 401);
  assert.equal(userRow('enroll@example.test').totp_enabled, 0);

  const ok = await client.send('POST', '/auth/mfa/enable', { code: right });
  assert.equal(ok.status, 200);
  assert.equal(userRow('enroll@example.test').totp_enabled, 1);

  assert.equal((await client.send('GET', MFA_PROTECTED)).status, 200);
  const me = await client.send('GET', '/auth/me');
  assert.deepEqual(me.json.mfa, { enabled: true, verified: true });
  assert.ok(!JSON.stringify(me.json).includes(setup.json.secret), '등록 뒤에는 비밀값을 다시 보여 주지 않음');
});

test('등록된 계정: 로그인 직후 403(mfa_required) → 맞는 코드 입력 후 200', async () => {
  await enrolledAccount('verify@example.test');
  const client = createClient(srv.baseUrl);
  const res = await client.send('POST', '/auth/login', { email: 'verify@example.test', password: FAKE_PASSWORD });
  assert.equal(res.json.mfa, 'verify_required');

  const before = await client.send('GET', '/memos');
  assert.equal(before.status, 403);
  assert.equal(before.json.error, 'mfa_required');

  srv.clock.advance(30_000);
  assert.equal((await verifyMfa(srv, client, 'verify@example.test')).status, 200);
  assert.equal((await client.send('GET', MFA_PROTECTED)).status, 200);
});

test('틀린 코드·형식이 다른 코드·누구나 아는 고정 번호는 모두 거부', async () => {
  const lenient = await startTestServer({ mfaLock: { maxFailures: 1000 } }); // 이 검사에서는 잠금에 걸리지 않게
  try {
    await signup(lenient.baseUrl, 'formats@example.test');
    await (await loginWithMfa(lenient, 'formats@example.test')).send('POST', '/auth/logout');
    const client = await login(lenient.baseUrl, 'formats@example.test');
    lenient.clock.advance(30_000);

    const secret = lenient.authenticatorApp.get('formats@example.test');
    const now = lenient.clock.now();
    const validNow = new Set([-30_000, 0, 30_000].map((d) => totpCode(secret, now + d)));
    const wellKnown = ['000000', '123456', '111111', '999999', '654321'].filter((c) => !validNow.has(c));
    const current = totpCode(secret, now);
    const malformed = [
      '12345', // 5자리
      '1234567', // 7자리
      Number(current), // 숫자 형식
      '１２３４５６', // 전각 숫자
      ` ${current}`, // 앞 공백
      `${current.slice(0, 5)}a`, // 문자 섞임
      '',
      null,
    ];
    for (const code of [...wellKnown, ...malformed]) {
      const res = await client.send('POST', '/auth/mfa/verify', { code });
      assert.equal(res.status, 401, `코드 ${JSON.stringify(code)} 는 거부되어야 함`);
      assert.equal(res.json.error, 'invalid_code');
    }
    assert.equal((await client.send('GET', '/memos')).status, 403, '여전히 추가 인증 전');
  } finally {
    await lenient.close();
  }
});

test('한 번 쓴 코드는 다시 쓸 수 없다 (로그아웃 후 같은 코드로 재로그인 시도)', async () => {
  await enrolledAccount('replay@example.test');
  srv.clock.advance(30_000);
  const code = totpCode(srv.authenticatorApp.get('replay@example.test'), srv.clock.now());

  const first = await login(srv.baseUrl, 'replay@example.test');
  assert.equal((await first.send('POST', '/auth/mfa/verify', { code })).status, 200);
  await first.send('POST', '/auth/logout');

  const second = await login(srv.baseUrl, 'replay@example.test');
  assert.equal((await second.send('POST', '/auth/mfa/verify', { code })).status, 401, '같은 30초 칸에서 재사용');
  srv.clock.advance(30_000);
  assert.equal((await second.send('POST', '/auth/mfa/verify', { code })).status, 401, '다음 칸(허용 오차 안)에서 재사용');
  assert.equal((await second.send('GET', '/memos')).status, 403);

  assert.equal((await verifyMfa(srv, second, 'replay@example.test')).status, 200, '새 칸의 새 코드는 통과');
});

test('허용 오차(앞뒤 30초)를 넘긴 옛 코드는 거부', async () => {
  await enrolledAccount('old-code@example.test');
  srv.clock.advance(30_000);
  const oldCode = totpCode(srv.authenticatorApp.get('old-code@example.test'), srv.clock.now());
  srv.clock.advance(90_000);
  const client = await login(srv.baseUrl, 'old-code@example.test');
  assert.equal((await client.send('POST', '/auth/mfa/verify', { code: oldCode })).status, 401);
});

test('요청 본문·헤더·주소로 "추가 인증을 마쳤다"고 우겨도 서버는 무시한다', async () => {
  await enrolledAccount('liar@example.test');
  const client = await login(srv.baseUrl, 'liar@example.test');
  const fake = { 'x-mfa-verified': 'true', 'x-mfa': '1' };
  assert.equal((await client.send('GET', '/memos?mfa=true&mfaVerified=1', undefined, fake)).status, 403);
  const post = await client.send('POST', '/memos', { title: '우기기', mfaVerified: true, mfa: { verified: true } }, fake);
  assert.equal(post.status, 403);
  const me = await client.send('GET', '/auth/me', undefined, fake);
  assert.equal(me.json.mfa.verified, false);
});

test('이미 등록된 계정은 비밀번호만으로 인증 앱을 다시 등록할 수 없다 (등록 바꿔치기 차단)', async () => {
  await enrolledAccount('takeover@example.test');
  const before = userRow('takeover@example.test').totp_secret;
  const attacker = await login(srv.baseUrl, 'takeover@example.test');

  const setup = await attacker.send('POST', '/auth/mfa/setup');
  assert.equal(setup.status, 409);
  assert.equal(setup.json.error, 'mfa_already_enabled');
  const enable = await attacker.send('POST', '/auth/mfa/enable', { code: '123456' });
  assert.equal(enable.status, 409);
  assert.equal(userRow('takeover@example.test').totp_secret, before, '등록된 비밀값이 바뀌면 안 됨');
});

test('추가 인증 5번 연속 실패 → 15분 잠금(맞는 코드도 429, 새로 로그인해도 429) → 시간이 지나면 풀림', async () => {
  await enrolledAccount('lock@example.test');
  const client = await login(srv.baseUrl, 'lock@example.test');
  srv.clock.advance(30_000);
  const secret = srv.authenticatorApp.get('lock@example.test');
  const valid = new Set([-30_000, 0, 30_000].map((d) => totpCode(secret, srv.clock.now() + d)));
  const wrong = ['000000', '000001', '000002', '000003', '000004', '000005'].filter((c) => !valid.has(c));

  for (let i = 0; i < 4; i++) assert.equal((await client.send('POST', '/auth/mfa/verify', { code: wrong[i] })).status, 401);
  const fifth = await client.send('POST', '/auth/mfa/verify', { code: wrong[4] });
  assert.equal(fifth.status, 429);
  assert.equal(fifth.json.error, 'mfa_locked');

  assert.equal((await verifyMfa(srv, client, 'lock@example.test')).status, 429, '잠금 중에는 맞는 코드도 거부');
  const otherSession = await login(srv.baseUrl, 'lock@example.test');
  assert.equal((await verifyMfa(srv, otherSession, 'lock@example.test')).status, 429, '세션을 바꿔도 계정 잠금 유지');

  srv.clock.advance(15 * 60_000 + 30_000);
  assert.equal((await verifyMfa(srv, otherSession, 'lock@example.test')).status, 200, '15분 뒤에는 풀림');
});

test('추가 인증에 성공하면 세션 번호가 바뀌고, 인증 전 쿠키로는 접근할 수 없다', async () => {
  await enrolledAccount('rotate@example.test');
  const client = await login(srv.baseUrl, 'rotate@example.test');
  const beforeMfa = client.cookie(SESSION_COOKIE);
  srv.clock.advance(30_000);
  assert.equal((await verifyMfa(srv, client, 'rotate@example.test')).status, 200);
  const afterMfa = client.cookie(SESSION_COOKIE);

  assert.notEqual(afterMfa, beforeMfa);
  assert.equal((await replay(beforeMfa)).status, 401, '인증 전 쿠키를 훔쳐 둬도 쓸 수 없음');
  assert.equal((await replay(afterMfa)).status, 200);
});

test('로그아웃하면 추가 인증까지 마친 세션도 회수된다 (예전 쿠키 재사용 401)', async () => {
  await signup(srv.baseUrl, 'logout-mfa@example.test');
  const client = await loginWithMfa(srv, 'logout-mfa@example.test');
  const cookie = client.cookie(SESSION_COOKIE);
  assert.equal((await replay(cookie)).status, 200);

  assert.equal((await client.send('POST', '/auth/logout')).status, 204);
  assert.equal((await replay(cookie)).status, 401);
  assert.equal((await replay(cookie, '/auth/me')).status, 401);
});

test('관리자 초기화(mfa-reset): 그 계정의 모든 세션이 끊기고, 다시 로그인하면 재등록부터', async () => {
  await signup(srv.baseUrl, 'lost-phone@example.test');
  const a = await loginWithMfa(srv, 'lost-phone@example.test');
  const b = await loginWithMfa(srv, 'lost-phone@example.test');
  const cookies = [a.cookie(SESSION_COOKIE), b.cookie(SESSION_COOKIE)];

  const result = resetMfa(srv.db, 'lost-phone@example.test');
  assert.equal(result.sessionsRevoked, 2);
  for (const c of cookies) assert.equal((await replay(c)).status, 401, '초기화 전 세션은 모두 회수');

  const again = createClient(srv.baseUrl);
  const res = await again.send('POST', '/auth/login', { email: 'lost-phone@example.test', password: FAKE_PASSWORD });
  assert.equal(res.json.mfa, 'setup_required');
  assert.equal(userRow('lost-phone@example.test').totp_secret, null);
  assert.throws(() => resetMfa(srv.db, 'nobody@example.test'), /없는 계정/);
});

test('순서를 건너뛴 요청: 등록 시작 없이 완료 400, 등록 안 된 계정의 확인 409, 로그인 없이 401', async () => {
  await signup(srv.baseUrl, 'order@example.test');
  const client = await login(srv.baseUrl, 'order@example.test');
  const enable = await client.send('POST', '/auth/mfa/enable', { code: '123456' });
  assert.equal(enable.status, 400);
  assert.equal(enable.json.error, 'mfa_setup_not_started');
  const verify = await client.send('POST', '/auth/mfa/verify', { code: '123456' });
  assert.equal(verify.status, 409);
  assert.equal(verify.json.error, 'mfa_not_enabled');

  for (const path of ['/auth/mfa/setup', '/auth/mfa/enable', '/auth/mfa/verify']) {
    assert.equal((await request(srv.baseUrl, 'POST', path, { code: '123456' })).status, 401, path);
  }
});

test('등록 시작(setup)만 하고 다른 세션에서 완료(enable)할 수는 없다', async () => {
  await signup(srv.baseUrl, 'split@example.test');
  const first = await login(srv.baseUrl, 'split@example.test');
  const setup = await first.send('POST', '/auth/mfa/setup');
  const second = await login(srv.baseUrl, 'split@example.test');
  srv.clock.advance(30_000);
  const res = await second.send('POST', '/auth/mfa/enable', { code: totpCode(setup.json.secret, srv.clock.now()) });
  assert.equal(res.status, 400);
  assert.equal(userRow('split@example.test').totp_enabled, 0);
});
