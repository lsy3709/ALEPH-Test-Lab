// 개발용 관리 도구(서버 API가 아님): 휴대폰을 잃어버린 실습 계정의 추가 인증을 초기화한다.
// 1) 등록된 비밀값·잠금 상태를 지우고 2) 그 계정의 서버 세션을 모두 끊는다(이미 로그인한 기기도 회수).
// 다음 로그인 때는 인증 앱 등록(setup)부터 다시 해야 한다.
// 사용법: npm run mfa-reset -- student1@example.test
const path = require('node:path');
const { openDb } = require('../src/db');

function resetMfa(db, rawEmail) {
  const email = String(rawEmail ?? '').trim().toLowerCase();
  const user = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
  if (!user) throw new Error(`없는 계정입니다: ${email}`);

  db.exec('BEGIN');
  try {
    db.prepare(
      `UPDATE users SET totp_secret = NULL, totp_enabled = 0, totp_last_step = NULL, totp_failures = 0, totp_locked_until = NULL
       WHERE id = ?`,
    ).run(user.id);
    const revoked = db.prepare("DELETE FROM sessions WHERE json_extract(sess, '$.userId') = ?").run(user.id).changes;
    db.exec('COMMIT');
    return { sessionsRevoked: revoked };
  } catch (err) {
    db.exec('ROLLBACK');
    throw err;
  }
}

if (require.main === module) {
  const email = process.argv[2];
  if (!email) {
    console.log('사용법: npm run mfa-reset -- student1@example.test');
    process.exit(1);
  }
  const DB_FILE = process.env.DB_FILE ?? path.join(__dirname, '..', 'data', 'app.db');
  const db = openDb(DB_FILE);
  try {
    const { sessionsRevoked } = resetMfa(db, email);
    console.log(`${email} 의 추가 인증을 초기화하고 로그인 세션 ${sessionsRevoked}개를 끊었습니다.`);
    console.log('인증 앱에 남아 있는 예전 MemoLab 항목은 지우고, 다음 로그인 때 다시 등록하세요.');
  } catch (err) {
    console.error(err.message);
    process.exitCode = 1;
  } finally {
    db.close();
  }
}

module.exports = { resetMfa };
