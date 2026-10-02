// 개발용 확인 도구(서버 API가 아님): 서버에 저장된 로그인 세션 목록을 "읽기 전용"으로 보여 준다.
// 목적: 로그인하면 서버 쪽에 세션이 실제로 생기고, 로그아웃하면 사라지는지 눈으로 확인하기.
// 세션 번호는 로그인 자격의 일부이므로 앞 6자만 보여 준다.
const fs = require('node:fs');
const path = require('node:path');
const { DatabaseSync } = require('node:sqlite');

const DB_FILE = process.env.DB_FILE ?? path.join(__dirname, '..', 'data', 'app.db');

if (!fs.existsSync(DB_FILE)) {
  console.log(`DB 파일이 없습니다: ${DB_FILE}\n먼저 npm start 로 서버를 한 번 실행하세요.`);
  process.exit(1);
}

const db = new DatabaseSync(DB_FILE, { readOnly: true });
const hasSessions = db.prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'sessions'").get();
if (!hasSessions) {
  console.log('sessions 표가 아직 없습니다. 3단계 코드로 npm start 를 한 번 실행하세요.');
  process.exit(1);
}

const users = new Map(db.prepare('SELECT id, email FROM users').all().map((u) => [u.id, u.email]));
const rows = db.prepare('SELECT sid, sess, expires_at FROM sessions ORDER BY expires_at').all();
const now = Date.now();

console.log(`서버에 저장된 세션: ${rows.length}개`);
if (rows.length > 0) {
  console.table(
    rows.map((r) => {
      const data = JSON.parse(r.sess);
      return {
        session: `${r.sid.slice(0, 6)}…`,
        user: users.get(data.userId) ?? '(없음)',
        expires: new Date(r.expires_at).toLocaleString('ko-KR'),
        expired: r.expires_at <= now ? '만료됨' : '',
      };
    }),
  );
}
db.close();
