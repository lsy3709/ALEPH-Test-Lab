// 비밀번호 규칙 검사, 해시 만들기·확인하기
// 해시 계산은 직접 만들지 않고 검증된 Argon2 라이브러리(@node-rs/argon2)에 맡긴다.
const argon2 = require('@node-rs/argon2');

const MIN_LENGTH = 10;
const MAX_LENGTH = 128;

// Argon2id 설정: OWASP 권장 최소값(메모리 19 MiB, 반복 2회, 병렬 1).
// 알고리즘은 라이브러리 기본값인 Argon2id 를 쓴다(검사에서 '$argon2id$' 로 확인).
const HASH_OPTIONS = { memoryCost: 19456, timeCost: 2, parallelism: 1 };

// 너무 흔해서 공격자가 가장 먼저 시도하는 비밀번호 일부(10자 이상만; 짧은 것은 길이에서 걸러짐).
// 실제 서비스는 유출된 비밀번호 수억 개 목록과 비교한다 — 여기서는 원리만 보여 주는 작은 목록.
const COMMON_PASSWORDS = new Set([
  'password123', 'password1234', 'passw0rd123', '1234567890', '12345678910', '0123456789',
  '1111111111', 'aaaaaaaaaa', 'qwertyuiop', 'qwerty12345', 'qwer123456', 'asdf123456',
  '1q2w3e4r5t', '1q2w3e4r5t6y', 'zxcvbnm123', 'iloveyou12', 'abcd123456', 'abc1234567',
  'admin12345', 'welcome123',
]);

// 정규화: 겉보기엔 같은 글자(예: 한글 완성형/조합형, 전각/반각)를 같은 문자열로 맞춘다.
function normalizePassword(password) {
  return password.normalize('NFKC');
}

// 규칙에 맞으면 null, 아니면 사용자에게 보여 줄 이유(문자열)를 돌려준다.
function checkPasswordPolicy(password, email) {
  if (typeof password !== 'string') return '비밀번호를 문자열로 입력하세요.';
  const pw = normalizePassword(password);
  if (pw.length < MIN_LENGTH || pw.length > MAX_LENGTH) {
    return `비밀번호는 ${MIN_LENGTH}~${MAX_LENGTH}자여야 합니다.`;
  }
  const lower = pw.toLowerCase();
  if (COMMON_PASSWORDS.has(lower)) return '너무 흔한 비밀번호입니다.';
  const emailId = email.split('@')[0];
  if (emailId.length >= 4 && lower.includes(emailId)) return '비밀번호에 이메일 아이디를 넣지 마세요.';
  return null;
}

// 해시 만들기: 실행할 때마다 무작위 솔트가 붙어 같은 비밀번호도 매번 다른 결과가 나온다.
async function hashPassword(password) {
  return argon2.hash(normalizePassword(password), HASH_OPTIONS);
}

// 해시 확인하기: 저장된 해시와 입력한 비밀번호가 맞는지. 해시가 망가졌으면 오류 대신 false.
async function verifyPassword(storedHash, password) {
  if (typeof storedHash !== 'string' || typeof password !== 'string') return false;
  try {
    return await argon2.verify(storedHash, normalizePassword(password));
  } catch {
    return false;
  }
}

module.exports = { checkPasswordPolicy, hashPassword, verifyPassword };
