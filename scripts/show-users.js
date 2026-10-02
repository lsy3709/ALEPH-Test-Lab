// 개발용 확인 도구(서버 API가 아님): 내 컴퓨터의 DB 파일을 "읽기 전용"으로 열어 사용자 표를 보여 준다.
// 목적: 비밀번호 원문 칸이 없다는 것과 해시가 어떻게 생겼는지 눈으로 확인하기.
// 서버 주소로는 이 정보에 접근할 수 없다 — 파일에 직접 접근할 수 있는 내 컴퓨터에서만 동작한다.
const fs = require('node:fs');
const path = require('node:path');
const { DatabaseSync } = require('node:sqlite');

const DB_FILE = process.env.DB_FILE ?? path.join(__dirname, '..', 'data', 'app.db');

if (!fs.existsSync(DB_FILE)) {
  console.log(`DB 파일이 없습니다: ${DB_FILE}\n먼저 npm start 로 서버를 한 번 실행하세요.`);
  process.exit(1);
}

const db = new DatabaseSync(DB_FILE, { readOnly: true });
const hasUsers = db.prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'users'").get();
if (!hasUsers) {
  console.log('users 표가 아직 없습니다. 2단계 코드로 npm start 를 한 번 실행하세요.');
  process.exit(1);
}

const columns = db.prepare('PRAGMA table_info(users)').all().map((c) => c.name);
console.log(`users 표의 칸: ${columns.join(', ')}`);

const rows = db.prepare('SELECT id, email, password_hash, created_at FROM users ORDER BY id').all();
console.table(
  rows.map((r) => ({
    id: r.id,
    email: r.email,
    password_hash: `${r.password_hash.slice(0, 40)}…(총 ${r.password_hash.length}자)`,
    created_at: r.created_at,
  })),
);
db.close();
