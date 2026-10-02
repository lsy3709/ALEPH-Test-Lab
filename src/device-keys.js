// 서버 쪽 기기 키 처리: 공개키 검사·지문 계산·서명 확인. Node 에 들어 있는 검증된 crypto 를 쓴다.
const crypto = require('node:crypto');

const PUBLIC_KEY_PATTERN = /^[A-Za-z0-9_-]{40,100}$/;
const SIGNATURE_PATTERN = /^[A-Za-z0-9_-]{86}$/; // Ed25519 서명 64바이트 = base64url 86자

// 클라이언트가 보낸 공개키 문자열을 검사한다. Ed25519 공개키가 아니면 null.
// 돌려주는 keyId(공개키 SHA-256 지문)로 "같은 기기인지"를 찾는다 — 기기 이름은 쓰지 않는다.
function parsePublicKey(text) {
  if (typeof text !== 'string' || !PUBLIC_KEY_PATTERN.test(text)) return null;
  try {
    const key = crypto.createPublicKey({ key: Buffer.from(text, 'base64url'), format: 'der', type: 'spki' });
    if (key.asymmetricKeyType !== 'ed25519') return null;
    const der = key.export({ type: 'spki', format: 'der' });
    return { key, publicKey: der.toString('base64url'), keyId: crypto.createHash('sha256').update(der).digest('base64url') };
  } catch {
    return null;
  }
}

// 서명 확인: 그 공개키의 짝인 개인키로 이 메시지에 서명했을 때만 true
function verifySignature(key, message, signature) {
  if (typeof signature !== 'string' || !SIGNATURE_PATTERN.test(signature)) return false;
  try {
    return crypto.verify(null, Buffer.from(message, 'utf8'), key, Buffer.from(signature, 'base64url'));
  } catch {
    return false;
  }
}

module.exports = { parsePublicKey, verifySignature };
