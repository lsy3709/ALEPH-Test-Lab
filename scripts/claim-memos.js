// 개발용 도구(서버 API가 아님): 3단계 이전에 만든 "주인 없는 메모"를 내 실습 계정에 연결한다.
// 서버 주소로는 할 수 없고, DB 파일에 직접 접근할 수 있는 내 컴퓨터에서만 실행된다.
// 사용법: npm run claim-memos -- student1@example.test
const path = require('node:path');
const { openDb } = require('../src/db');

function assignOrphanMemos(db, rawEmail) {
  const email = String(rawEmail ?? '').trim().toLowerCase();
  const user = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
  if (!user) throw new Error(`없는 계정입니다: ${email}`);
  return db.prepare('UPDATE memos SET user_id = ? WHERE user_id IS NULL').run(user.id).changes;
}

if (require.main === module) {
  const email = process.argv[2];
  if (!email) {
    console.log('사용법: npm run claim-memos -- student1@example.test');
    process.exit(1);
  }
  const DB_FILE = process.env.DB_FILE ?? path.join(__dirname, '..', 'data', 'app.db');
  const db = openDb(DB_FILE);
  try {
    const count = assignOrphanMemos(db, email);
    console.log(`주인 없는 메모 ${count}개를 ${email} 계정에 연결했습니다.`);
  } catch (err) {
    console.error(err.message);
    process.exitCode = 1;
  } finally {
    db.close();
  }
}

module.exports = { assignOrphanMemos };
