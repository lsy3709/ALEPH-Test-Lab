// 기기 도우미(클라이언트 쪽 프로그램 — 서버가 아님)
// 이 컴퓨터의 "기기 폴더"(devices/<이름>/)에 Ed25519 개인키를 만들어 두고, 서버가 낸 문제(challenge)에 서명한다.
// 개인키는 이 폴더 밖으로 나가지 않는다. 서버에는 공개키와 서명만 보낸다.
// 암호 계산은 직접 만들지 않고 Node 에 들어 있는 검증된 crypto(OpenSSL)를 쓴다.
//
// 사용법(PowerShell 7, 프로젝트 폴더에서):
//   npm run device -- init device-a                              기기 키 만들기
//   $ch.message | npm run device --silent -- proof device-a       서명해서 서버에 보낼 JSON 출력
//   npm run device -- show device-a                              공개 정보 보기(개인키는 안 보여 줌)
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const DEVICES_DIR = process.env.DEVICES_DIR ?? path.join(__dirname, '..', 'devices');
const NAME_PATTERN = /^[a-z0-9][a-z0-9-]{0,29}$/; // 폴더 이름: 영문 소문자·숫자·- 만(../ 같은 경로 탈출 차단)
// 서버 문제 형식: memo-lab:<목적>:<무작위 43자>:<사용자 번호>. 이 형식이 아닌 내용에는 서명하지 않는다.
const MESSAGE_PATTERN = /^memo-lab:(register|login):[A-Za-z0-9_-]{43}:[1-9][0-9]{0,9}$/;

// 수업용 "모의 보안 상태": 이 기기가 스스로 주장하는 값일 뿐, 서버는 허용 판단에 쓰지 않는다.
const MOCK_POSTURE = { osUpdated: true, diskEncrypted: true, screenLock: true };

// 새 키 쌍 만들기. 공개키는 서버에 보낼 수 있는 문자열(SPKI DER → base64url), 개인키는 객체 그대로.
function createDeviceKeys() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  return { publicKey: publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'), privateKey };
}

// 서버 문제에 서명해 서버로 보낼 내용을 만든다. name·posture 는 이름표·참고용일 뿐 증명이 아니다.
function proofFor(message, { privateKey, publicKey, name, posture }) {
  if (typeof message !== 'string' || !MESSAGE_PATTERN.test(message)) {
    throw new Error('서버 문제(challenge) 형식이 아닙니다. 다른 내용에는 서명하지 않습니다.');
  }
  const signature = crypto.sign(null, Buffer.from(message, 'utf8'), privateKey).toString('base64url');
  return { name, publicKey, signature, posture };
}

function deviceDir(name, baseDir) {
  if (typeof name !== 'string' || !NAME_PATTERN.test(name)) {
    throw new Error('기기 이름은 영문 소문자·숫자·-(하이픈)만, 30자 이하로 정하세요. 예: device-a');
  }
  return path.join(baseDir, name);
}

// 기기 폴더 만들기: private-key.pem(개인키) + device.json(공개 정보·모의 상태). 이미 있으면 덮어쓰지 않는다.
function initDevice(name, baseDir = DEVICES_DIR) {
  const dir = deviceDir(name, baseDir);
  if (fs.existsSync(dir)) throw new Error(`이미 있는 기기 폴더입니다: ${dir} (덮어쓰지 않습니다)`);
  fs.mkdirSync(dir, { recursive: true });
  const { publicKey, privateKey } = createDeviceKeys();
  fs.writeFileSync(path.join(dir, 'private-key.pem'), privateKey.export({ type: 'pkcs8', format: 'pem' }), {
    flag: 'wx',
    mode: 0o600,
  });
  const info = {
    name,
    publicKey,
    mockPosture: MOCK_POSTURE,
    note: 'mockPosture 는 수업용 모의 값입니다. 서버는 이 값을 믿지 않습니다. private-key.pem 은 공유하지 마세요.',
  };
  fs.writeFileSync(path.join(dir, 'device.json'), `${JSON.stringify(info, null, 2)}\n`, { flag: 'wx' });
  return { dir, publicKey };
}

// 기기 폴더 불러오기 → proofFor 에 바로 넘길 수 있는 모양
function loadDevice(name, baseDir = DEVICES_DIR) {
  const dir = deviceDir(name, baseDir);
  const info = JSON.parse(fs.readFileSync(path.join(dir, 'device.json'), 'utf8'));
  const privateKey = crypto.createPrivateKey(fs.readFileSync(path.join(dir, 'private-key.pem')));
  return { name: info.name, publicKey: info.publicKey, posture: info.mockPosture, privateKey };
}

const keyIdOf = (publicKey) => crypto.createHash('sha256').update(Buffer.from(publicKey, 'base64url')).digest('base64url');

// 파이프로 들어온 입력을 끝까지 읽는다(끝의 줄바꿈 제거)
function readStdin() {
  return new Promise((resolve, reject) => {
    const chunks = [];
    process.stdin.on('data', (chunk) => chunks.push(chunk));
    process.stdin.on('end', () => resolve(Buffer.concat(chunks).toString('utf8').trim()));
    process.stdin.on('error', reject);
  });
}

async function main([command, name]) {
  if (command === 'init') {
    const { dir, publicKey } = initDevice(name);
    console.log(`기기 키를 만들었습니다: ${dir}`);
    console.log(`  공개키 지문(앞 16자): ${keyIdOf(publicKey).slice(0, 16)}`);
    console.log('  private-key.pem 은 이 컴퓨터에만 두세요(Git 에서 제외됨).');
  } else if (command === 'proof') {
    if (process.stdin.isTTY) throw new Error("서버 문제를 파이프로 넘겨 주세요. 예: $ch.message | npm run device --silent -- proof device-a");
    const message = await readStdin();
    process.stdout.write(JSON.stringify(proofFor(message, loadDevice(name))));
  } else if (command === 'show') {
    const device = loadDevice(name);
    console.log(JSON.stringify({ name: device.name, keyId: keyIdOf(device.publicKey), publicKey: device.publicKey, mockPosture: device.posture }, null, 2));
  } else {
    console.log('사용법: npm run device -- init|show <기기이름>  /  $ch.message | npm run device --silent -- proof <기기이름>');
    process.exitCode = 1;
  }
}

if (require.main === module) {
  main(process.argv.slice(2)).catch((err) => {
    console.error(`기기 도우미 오류: ${err.message}`);
    process.exitCode = 1;
  });
}

module.exports = { createDeviceKeys, proofFor, initDevice, loadDevice, MESSAGE_PATTERN };
