// 데이터베이스(SQLite) 연결과 표(테이블) 준비
const { DatabaseSync } = require('node:sqlite');

// file: 데이터베이스 파일 경로. 테스트에서는 ':memory:'(메모리에만 잠깐 존재)를 쓴다.
function openDb(file) {
  const db = new DatabaseSync(file);
  db.exec('PRAGMA foreign_keys = ON;');
  migrate(db);
  return db;
}

// 마이그레이션: DB 구조를 단계별로 바꾸는 작업.
// user_version 번호로 "어디까지 적용했는지" 기억하므로, 이미 쌓인 데이터는 지우지 않고 다음 단계만 덧붙인다.
function migrate(db) {
  const { user_version: version } = db.prepare('PRAGMA user_version').get();

  if (version < 1) {
    db.exec(`
      BEGIN;
      CREATE TABLE memos (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        title      TEXT NOT NULL,
        body       TEXT NOT NULL DEFAULT '',
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
      );
      PRAGMA user_version = 1;
      COMMIT;
    `);
  }

  // 2단계: 사용자 표. 비밀번호는 원문이 아니라 해시(password_hash)만 저장한다.
  if (version < 2) {
    db.exec(`
      BEGIN;
      CREATE TABLE users (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        email         TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        created_at    TEXT NOT NULL DEFAULT (datetime('now'))
      );
      PRAGMA user_version = 2;
      COMMIT;
    `);
  }
}

module.exports = { openDb };
