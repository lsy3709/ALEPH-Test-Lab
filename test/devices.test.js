// 5단계 검사: 기기 등록·기기 확인(서명)·만료·차단·재등록
const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const {
  SESSION_COOKIE,
  startTestServer,
  request,
  signup,
  login,
  loginWithMfa,
  verifyMfa,
  testDevice,
  registerDevice,
  verifyDevice,
  loginFull,
} = require('./helpers');

const DAY = 24 * 60 * 60 * 1000;

let srv;
before(async () => {
  srv = await startTestServer();
});
after(async () => {
  await srv.close();
});

const deviceRows = (email) =>
  srv.db
    .prepare('SELECT d.* FROM devices d JOIN users u ON u.id = d.user_id WHERE u.email = ? ORDER BY d.created_at, d.rowid')
    .all(email);
const replay = (cookie, path = '/memos') => request(srv.baseUrl, 'GET', path, undefined, { cookie: `${SESSION_COOKIE}=${cookie}` });
const challenge = async (client, purpose) => (await client.send('POST', '/devices/challenge', { purpose })).json.message;

// 가입 + 추가 인증 등록 + 기기 1대 등록 후 로그아웃 → 등록한 기기(키 쌍)를 돌려준다
async function accountWithDevice(email) {
  await signup(srv.baseUrl, email);
  const client = await loginFull(srv, email);
  await client.send('POST', '/auth/logout');
  return srv.devices.get(email);
}

test('추가 인증까지 마쳐도 기기 확인 전에는 메모 API 403 (device_required)', async () => {
  await signup(srv.baseUrl, 'no-device@example.test');
  const client = await loginWithMfa(srv, 'no-device@example.test');
  for (const [method, path, body] of [['GET', '/memos'], ['POST', '/memos', { title: '무단' }], ['GET', '/memos/1'], ['DELETE', '/memos/1']]) {
    const res = await client.send(method, path, body);
    assert.equal(res.status, 403, `${method} ${path}`);
    assert.equal(res.json.error, 'device_required');
  }
});

test('기기 등록: 추가 인증 직후 등록 → 201, 그 세션은 바로 메모 사용, 서버에는 공개키만 저장', async () => {
  await signup(srv.baseUrl, 'register@example.test');
  const client = await loginWithMfa(srv, 'register@example.test');
  const device = testDevice('laptop-a');

  const res = await registerDevice(client, device);
  assert.equal(res.status, 201);
  assert.equal(res.json.device.name, 'laptop-a');
  assert.equal(res.json.device.state, 'active');
  assert.equal(new Date(res.json.device.expiresAt).getTime(), srv.clock.now() + 30 * DAY, '유효기간 30일');

  assert.equal((await client.send('GET', '/memos')).status, 200);
  const [row] = deviceRows('register@example.test');
  assert.equal(row.public_key, device.publicKey);
  assert.ok(!Object.values(row).some((v) => String(v).includes('PRIVATE')), '서버에는 개인키가 없어야 함');

  const me = await client.send('GET', '/auth/me');
  assert.deepEqual({ name: me.json.device.name, state: me.json.device.state }, { name: 'laptop-a', state: 'active' });
});

test('다시 로그인: 등록된 기기로 서명하면 200, 그 뒤 메모 사용 가능', async () => {
  const device = await accountWithDevice('relogin@example.test');
  const client = await loginWithMfa(srv, 'relogin@example.test');
  assert.equal((await client.send('GET', '/memos')).status, 403);

  const res = await verifyDevice(client, device);
  assert.equal(res.status, 200);
  assert.equal((await client.send('GET', '/memos')).status, 200);
  assert.ok(deviceRows('relogin@example.test')[0].last_used_at, '마지막 사용 시각 기록');
});

test('미등록 기기(등록 안 된 키)로 서명 → 403 device_not_registered', async () => {
  await accountWithDevice('stranger@example.test');
  const client = await loginWithMfa(srv, 'stranger@example.test');
  const res = await verifyDevice(client, testDevice('unknown-laptop'));
  assert.equal(res.status, 403);
  assert.equal(res.json.error, 'device_not_registered');
  assert.equal((await client.send('GET', '/memos')).status, 403);
});

test('기기 이름·기기 번호 헤더·브라우저 정보·모의 보안 상태를 흉내 내도 키가 다르면 거부', async () => {
  const real = await accountWithDevice('spoof@example.test');
  const realRow = deviceRows('spoof@example.test')[0];
  const client = await loginWithMfa(srv, 'spoof@example.test');
  const fakeHeaders = { 'x-device-id': realRow.id, 'x-device-name': real.name, 'user-agent': 'MemoLab-Trusted-Browser' };

  assert.equal((await client.send('GET', '/memos', undefined, fakeHeaders)).status, 403, '헤더만으로는 통과 불가');

  // 등록된 기기와 같은 이름 + 완벽한 "보안 상태"를 주장하는 다른 키
  const impostor = testDevice(real.name, { osUpdated: true, diskEncrypted: true, screenLock: true, antivirus: true });
  const message = await challenge(client, 'login');
  const res = await client.send('POST', '/devices/verify', { ...impostor.proof(message), deviceId: realRow.id }, fakeHeaders);
  assert.equal(res.status, 403);
  assert.equal(res.json.error, 'device_not_registered');
  assert.equal((await client.send('GET', '/memos', undefined, fakeHeaders)).status, 403);
});

test('등록된 기기의 공개키를 그대로 보내도, 그 기기의 개인키로 만든 서명이 아니면 401', async () => {
  const real = await accountWithDevice('pubkey-thief@example.test');
  const client = await loginWithMfa(srv, 'pubkey-thief@example.test');
  const thief = testDevice('thief');

  const forged = thief.proof(await challenge(client, 'login'));
  const res = await client.send('POST', '/devices/verify', { publicKey: real.publicKey, signature: forged.signature });
  assert.equal(res.status, 401);
  assert.equal(res.json.error, 'invalid_signature');

  await challenge(client, 'login');
  const junk = await client.send('POST', '/devices/verify', { publicKey: real.publicKey, signature: 'A'.repeat(86) });
  assert.equal(junk.status, 401);
  assert.equal((await client.send('GET', '/memos')).status, 403);
});

test('서버 문제(challenge)는 한 번만, 2분 안에만, 정해진 목적에만 쓸 수 있다', async () => {
  const device = await accountWithDevice('challenge@example.test');
  const client = await loginWithMfa(srv, 'challenge@example.test');

  // ① 성공한 서명을 그대로 다시 보내기
  const body = device.proof(await challenge(client, 'login'));
  assert.equal((await client.send('POST', '/devices/verify', body)).status, 200);
  const again = await client.send('POST', '/devices/verify', body);
  assert.equal(again.status, 400);
  assert.equal(again.json.error, 'challenge_missing');

  // ② 2분이 지난 문제
  const late = await challenge(client, 'login');
  srv.clock.advance(2 * 60_000 + 1000);
  const expired = await client.send('POST', '/devices/verify', device.proof(late));
  assert.equal(expired.status, 400);
  assert.equal(expired.json.error, 'challenge_expired');

  // ③ 등록용 문제로 로그인 확인
  const wrongPurpose = await client.send('POST', '/devices/verify', device.proof(await challenge(client, 'register')));
  assert.equal(wrongPurpose.status, 400);
  assert.equal(wrongPurpose.json.error, 'challenge_mismatch');

  // ④ 문제의 사용자 번호를 바꿔 서명
  const original = await challenge(client, 'login');
  const tampered = original.replace(/:(\d+)$/, (m, id) => `:${Number(id) + 1}`);
  const res = await client.send('POST', '/devices/verify', device.proof(tampered));
  assert.equal(res.status, 401);
  assert.equal(res.json.error, 'invalid_signature');

  // ⑤ 실패한 문제도 버려진다: 같은 문제에 올바른 서명을 다시 내도 400
  const retry = await client.send('POST', '/devices/verify', device.proof(original));
  assert.equal(retry.status, 400);
  assert.equal(retry.json.error, 'challenge_missing');
});

test('추가 인증 후 5분이 지나면 기기 등록 거부(403 recent_mfa_required) → 새 코드로 다시 인증하면 등록 가능', async () => {
  await signup(srv.baseUrl, 'slow@example.test');
  const client = await loginWithMfa(srv, 'slow@example.test');
  const device = testDevice('slow-laptop');
  srv.clock.advance(5 * 60_000 + 1000);

  const res = await registerDevice(client, device);
  assert.equal(res.status, 403);
  assert.equal(res.json.error, 'recent_mfa_required');
  assert.equal(deviceRows('slow@example.test').length, 0);

  srv.clock.advance(30_000);
  assert.equal((await verifyMfa(srv, client, 'slow@example.test')).status, 200);
  assert.equal((await registerDevice(client, device)).status, 201);
});

test('계정당 활성 기기는 3대까지: 4번째 409 device_limit → 하나 차단하면 다시 등록 가능', async () => {
  await signup(srv.baseUrl, 'many@example.test');
  const client = await loginWithMfa(srv, 'many@example.test');
  const devices = [1, 2, 3, 4].map((i) => testDevice(`many-${i}`));

  for (const d of devices.slice(0, 3)) assert.equal((await registerDevice(client, d)).status, 201);
  const fourth = await registerDevice(client, devices[3]);
  assert.equal(fourth.status, 409);
  assert.equal(fourth.json.error, 'device_limit');

  const list = await client.send('GET', '/devices');
  assert.equal(list.json.devices.length, 3);
  assert.equal((await client.send('POST', `/devices/${list.json.devices[0].id}/block`)).status, 200);
  assert.equal((await registerDevice(client, devices[3])).status, 201);
});

test('차단: 그 기기로 접속 중이던 세션도 즉시 403, 다시 서명해도 403, 같은 키 재등록 409, 새 키는 등록 가능', async () => {
  const device = await accountWithDevice('block@example.test');
  const onDevice = await loginWithMfa(srv, 'block@example.test');
  assert.equal((await verifyDevice(onDevice, device)).status, 200);
  assert.equal((await onDevice.send('GET', '/memos')).status, 200);

  // 다른 곳에서 로그인·추가 인증한 뒤 "분실 신고"로 차단
  const manager = await loginWithMfa(srv, 'block@example.test');
  const [target] = (await manager.send('GET', '/devices')).json.devices;
  const blocked = await manager.send('POST', `/devices/${target.id}/block`);
  assert.equal(blocked.status, 200);
  assert.equal(blocked.json.device.state, 'blocked');

  const r1 = await onDevice.send('GET', '/memos');
  assert.equal(r1.status, 403);
  assert.equal(r1.json.error, 'device_blocked');
  const r2 = await verifyDevice(onDevice, device);
  assert.equal(r2.status, 403);
  assert.equal(r2.json.error, 'device_blocked');
  const r3 = await registerDevice(manager, device);
  assert.equal(r3.status, 409);
  assert.equal(r3.json.error, 'device_blocked');

  assert.equal((await registerDevice(manager, testDevice('replacement'))).status, 201, '새 키로 만든 기기는 등록 가능');
});

test('만료(30일): 접속 중 세션도 403, 로그인 서명도 403 → 추가 인증 후 같은 키로 재등록하면 30일 연장', async () => {
  const device = await accountWithDevice('expire@example.test');
  const client = await loginWithMfa(srv, 'expire@example.test');
  assert.equal((await verifyDevice(client, device)).status, 200);
  assert.equal((await client.send('GET', '/memos')).status, 200);

  srv.clock.advance(30 * DAY + 1000);
  const r1 = await client.send('GET', '/memos');
  assert.equal(r1.status, 403);
  assert.equal(r1.json.error, 'device_expired');
  const r2 = await verifyDevice(client, device);
  assert.equal(r2.status, 403);
  assert.equal(r2.json.error, 'device_expired');

  srv.clock.advance(30_000);
  assert.equal((await verifyMfa(srv, client, 'expire@example.test')).status, 200);
  const renew = await registerDevice(client, device);
  assert.equal(renew.status, 200);
  assert.equal(renew.json.renewed, true);
  assert.equal(new Date(renew.json.device.expiresAt).getTime(), srv.clock.now() + 30 * DAY);
  assert.equal(deviceRows('expire@example.test').length, 1, '새 기기가 아니라 같은 기기를 연장');
  assert.equal((await client.send('GET', '/memos')).status, 200);
});

test('남의 기기: 목록에 안 보이고 차단은 404, 남의 기기 키로 내 계정 확인도 403', async () => {
  const aDevice = await accountWithDevice('owner-a@example.test');
  const aRow = deviceRows('owner-a@example.test')[0];
  await signup(srv.baseUrl, 'owner-b@example.test');
  const b = await loginFull(srv, 'owner-b@example.test');

  const list = await b.send('GET', '/devices');
  assert.ok(!list.json.devices.some((d) => d.id === aRow.id));
  assert.equal((await b.send('POST', `/devices/${aRow.id}/block`)).status, 404);
  assert.equal(deviceRows('owner-a@example.test')[0].status, 'active');

  const b2 = await loginWithMfa(srv, 'owner-b@example.test');
  const res = await verifyDevice(b2, aDevice); // A 의 기기(개인키 포함)를 B 계정에 써 보기
  assert.equal(res.status, 403);
  assert.equal(res.json.error, 'device_not_registered');
});

test('기기 확인에 성공하면 세션 번호가 바뀌고, 로그아웃하면 그 세션도 회수된다', async () => {
  const device = await accountWithDevice('rotate-device@example.test');
  const client = await loginWithMfa(srv, 'rotate-device@example.test');
  const beforeDevice = client.cookie(SESSION_COOKIE);
  assert.equal((await verifyDevice(client, device)).status, 200);
  const afterDevice = client.cookie(SESSION_COOKIE);

  assert.notEqual(afterDevice, beforeDevice);
  assert.equal((await replay(beforeDevice)).status, 401);
  assert.equal((await replay(afterDevice)).status, 200);

  assert.equal((await client.send('POST', '/auth/logout')).status, 204);
  assert.equal((await replay(afterDevice)).status, 401, '로그아웃 후 쿠키 재사용 거부');
});

test('잘못된 입력은 거부하고 아무것도 저장하지 않는다 (목적·공개키 형식·다른 종류 키·이름표 길이·id 형식)', async () => {
  await signup(srv.baseUrl, 'inputs@example.test');
  const client = await loginWithMfa(srv, 'inputs@example.test');
  const device = testDevice('ok-name');

  const badPurpose = await client.send('POST', '/devices/challenge', { purpose: 'admin' });
  assert.equal(badPurpose.status, 400);
  assert.equal(badPurpose.json.error, 'invalid_purpose');

  const x25519 = crypto.generateKeyPairSync('x25519').publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
  for (const publicKey of ['not-a-key', x25519, 12345]) {
    const res = await client.send('POST', '/devices', { ...device.proof(await challenge(client, 'register')), publicKey });
    assert.equal(res.status, 400, `공개키 ${String(publicKey).slice(0, 12)}`);
    assert.equal(res.json.error, 'invalid_public_key');
  }
  for (const name of ['', 'x'.repeat(41), 7]) {
    const res = await client.send('POST', '/devices', { ...device.proof(await challenge(client, 'register')), name });
    assert.equal(res.status, 400);
    assert.equal(res.json.error, 'invalid_device_name');
  }
  assert.equal((await client.send('POST', '/devices/not-a-uuid/block')).status, 404);
  assert.equal(deviceRows('inputs@example.test').length, 0);
});

test('로그인·추가 인증 없이는 기기 주소도 쓸 수 없다', async () => {
  assert.equal((await request(srv.baseUrl, 'POST', '/devices/challenge', { purpose: 'login' })).status, 401);
  assert.equal((await request(srv.baseUrl, 'GET', '/devices')).status, 401);
  await signup(srv.baseUrl, 'password-only@example.test');
  const client = await login(srv.baseUrl, 'password-only@example.test');
  assert.equal((await client.send('GET', '/devices')).status, 403);
  assert.equal((await client.send('POST', '/devices/challenge', { purpose: 'register' })).status, 403);
});
