// 개발용 관리 도구(서버 API가 아님): 실습 계정의 비밀번호를 새로 정한다.
// - 새 비밀번호는 명령줄 인자로 받지 않는다(명령 기록·프로세스 목록에 남기 때문). 표준 입력으로 받는다.
// - 2단계와 같은 비밀번호 규칙으로 검사하고 Argon2id 해시만 저장한다.
// - 바꾸면 그 계정의 로그인 세션을 모두 끊는다. 추가 인증(인증 앱) 등록은 그대로 둔다.
// 사용법(PowerShell 7): Read-Host '새 비밀번호' -MaskInput | npm run password-reset --silent -- student1@example.test
const path = require('node:path');
const { openDb } = require('../src/db');
const { checkPasswordPolicy, hashPassword, verifyPassword } = require('../src/passwords');

async function resetPassword(db, rawEmail, newPassword) {
  const email = String(rawEmail ?? '').trim().toLowerCase();
  const user = db.prepare('SELECT id, password_hash FROM users WHERE email = ?').get(email);
  if (!user) throw new Error(`없는 계정입니다: ${email}`);

  const problem = checkPasswordPolicy(newPassword, email);
  if (problem) throw new Error(problem);
  if (await verifyPassword(user.password_hash, newPassword)) {
    throw new Error('지금 쓰는 비밀번호와 같습니다. 다른 비밀번호를 정하세요.');
  }
  const passwordHash = await hashPassword(newPassword);

  db.exec('BEGIN');
  try {
    db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(passwordHash, user.id);
    // 옛 비밀번호로 로그인해 있던 사람(나든 남이든)을 모두 내보낸다
    const revoked = db.prepare("DELETE FROM sessions WHERE json_extract(sess, '$.userId') = ?").run(user.id).changes;
    db.exec('COMMIT');
    return { sessionsRevoked: revoked };
  } catch (err) {
    db.exec('ROLLBACK');
    throw err;
  }
}

// 파이프로 들어온 입력을 끝까지 읽는다(끝의 줄바꿈 한 개만 제거)
function readStdin() {
  return new Promise((resolve, reject) => {
    const chunks = [];
    process.stdin.on('data', (chunk) => chunks.push(chunk));
    process.stdin.on('end', () => resolve(Buffer.concat(chunks).toString('utf8').replace(/\r?\n$/, '')));
    process.stdin.on('error', reject);
  });
}

if (require.main === module) {
  (async () => {
    const email = process.argv[2];
    if (!email || process.stdin.isTTY) {
      console.log("사용법(PowerShell 7): Read-Host '새 비밀번호' -MaskInput | npm run password-reset --silent -- student1@example.test");
      process.exitCode = 1;
      return;
    }
    const password = await readStdin();
    const DB_FILE = process.env.DB_FILE ?? path.join(__dirname, '..', 'data', 'app.db');
    const db = openDb(DB_FILE);
    try {
      const { sessionsRevoked } = await resetPassword(db, email, password);
      console.log(`${email} 의 비밀번호를 바꾸고 로그인 세션 ${sessionsRevoked}개를 끊었습니다. (추가 인증 등록 상태는 그대로)`);
    } catch (err) {
      console.error(`바꾸지 못했습니다: ${err.message}`);
      process.exitCode = 1;
    } finally {
      db.close();
    }
  })();
}

module.exports = { resetPassword };
