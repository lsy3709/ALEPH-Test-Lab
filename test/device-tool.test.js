// 5단계 검사: 기기 도우미(scripts/device.js) — 학생 컴퓨터에서 개인키를 만들고 서명하는 프로그램
const { test } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createDeviceKeys, proofFor, initDevice, loadDevice } = require('../scripts/device');

const VALID = `memo-lab:login:${'A'.repeat(43)}:1`;

test('기기 도우미는 서버 문제(challenge) 형식의 메시지에만 서명한다', () => {
  const keys = createDeviceKeys();
  const proof = proofFor(VALID, { ...keys, name: 'device-a' });
  const publicKey = crypto.createPublicKey({ key: Buffer.from(proof.publicKey, 'base64url'), format: 'der', type: 'spki' });
  assert.ok(crypto.verify(null, Buffer.from(VALID), publicKey, Buffer.from(proof.signature, 'base64url')));

  const notChallenges = [
    '계좌 이체 100만원 승인', // 아무 문장
    `memo-lab:admin:${'A'.repeat(43)}:1`, // 정해지지 않은 목적
    'memo-lab:login:short:1', // 문제 번호 형식이 다름
    `${VALID}\n추가 문장`, // 뒤에 덧붙임
    123,
  ];
  for (const message of notChallenges) {
    assert.throws(() => proofFor(message, { ...keys, name: 'device-a' }), /형식/, String(message));
  }
});

test('기기 폴더: 만들기·불러오기, 이미 있으면 덮어쓰지 않고, 폴더 이름으로 다른 경로에 쓸 수 없다', () => {
  // 기기 폴더(base)를 임시 폴더(parent) 한 단계 아래에 둔다.
  // 만약 이름 검사가 뚫려 '../evil' 이 base 밖으로 나가더라도 parent 안에 떨어져 검사 후 함께 지워진다.
  const parent = fs.mkdtempSync(path.join(os.tmpdir(), 'memo-lab-devices-'));
  const base = path.join(parent, 'devices');
  try {
    const created = initDevice('device-a', base);
    const pem = fs.readFileSync(path.join(base, 'device-a', 'private-key.pem'), 'utf8');
    const info = JSON.parse(fs.readFileSync(path.join(base, 'device-a', 'device.json'), 'utf8'));
    assert.match(pem, /BEGIN PRIVATE KEY/);
    assert.equal(info.publicKey, created.publicKey);
    assert.ok(!JSON.stringify(info).includes('PRIVATE'), 'device.json 에는 개인키가 없어야 함');

    assert.throws(() => initDevice('device-a', base), /이미/);
    for (const bad of ['../evil', '..', 'Device A', 'a/b', 'a\\b', '']) {
      assert.throws(() => initDevice(bad, base), /이름/, JSON.stringify(bad));
    }
    assert.ok(!fs.existsSync(path.join(parent, 'evil')), '기기 폴더 밖에 아무것도 생기면 안 됨');

    const loaded = loadDevice('device-a', base);
    const proof = proofFor(VALID, loaded);
    assert.equal(proof.publicKey, created.publicKey);
    assert.deepEqual(proof.posture, info.mockPosture, '모의 보안 상태는 device.json 값 그대로 보냄');
  } finally {
    fs.rmSync(parent, { recursive: true, force: true });
  }
});
