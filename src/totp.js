// TOTP(시간 기반 일회용 코드) 계산은 직접 만들지 않고 검증된 otpauth 라이브러리에 맡긴다.
// 휴대폰 인증 앱(Google Authenticator, Microsoft Authenticator 등)의 기본 설정과 같은 값을 쓴다.
const OTPAuth = require('otpauth');

const ISSUER = 'MemoLab'; // 인증 앱 목록에 보이는 서비스 이름
const PERIOD_SECONDS = 30; // 30초마다 코드가 바뀜
const DIGITS = 6;
const ALGORITHM = 'SHA1';
const WINDOW = 1; // 휴대폰 시계가 조금 어긋나도 되도록 앞뒤 30초 칸까지 인정
const CODE_PATTERN = /^[0-9]{6}$/; // 정확히 ASCII 숫자 6자리만

const totpFor = (secret, label) =>
  new OTPAuth.TOTP({
    issuer: ISSUER,
    label,
    secret: OTPAuth.Secret.fromBase32(secret),
    algorithm: ALGORITHM,
    digits: DIGITS,
    period: PERIOD_SECONDS,
  });

// 무작위 20바이트(160비트) 비밀값을 만든다. 사용자마다 다르고 서버가 정해 둔 고정값이 없다.
function newSecret() {
  return new OTPAuth.Secret({ size: 20 }).base32;
}

// 인증 앱 등록용 주소(QR 코드로 만들 수 있는 otpauth://totp/... 형식)
function otpauthUrl(secret, email) {
  return totpFor(secret, email).toString();
}

// 코드가 맞으면 그 코드가 속한 30초 칸 번호(step)를, 틀리면 null 을 돌려준다.
// step 은 "같은 코드 재사용"을 막을 때 쓴다(이미 통과한 칸 이하의 코드는 거부).
function checkCode(secret, code, nowMs) {
  if (typeof code !== 'string' || !CODE_PATTERN.test(code)) return null;
  const delta = totpFor(secret, ISSUER).validate({ token: code, timestamp: nowMs, window: WINDOW });
  if (delta === null) return null;
  return Math.floor(nowMs / 1000 / PERIOD_SECONDS) + delta;
}

module.exports = { newSecret, otpauthUrl, checkCode };
