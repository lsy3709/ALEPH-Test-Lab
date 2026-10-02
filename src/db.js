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

  // 3단계: 메모에 주인(user_id)을 붙이고, 로그인 세션을 서버 쪽 표에 저장한다.
  // 이전 단계에서 만든 메모는 지우지 않고 user_id = NULL(주인 없음)로 남긴다 → 아무에게도 보이지 않음.
  if (version < 3) {
    db.exec(`
      BEGIN;
      ALTER TABLE memos ADD COLUMN user_id INTEGER REFERENCES users(id) ON DELETE CASCADE;
      CREATE INDEX memos_user_id ON memos(user_id);
      CREATE TABLE sessions (
        sid        TEXT PRIMARY KEY,
        sess       TEXT NOT NULL,
        expires_at INTEGER NOT NULL
      );
      CREATE INDEX sessions_expires_at ON sessions(expires_at);
      PRAGMA user_version = 3;
      COMMIT;
    `);
  }

  // 4단계: 추가 인증(TOTP). 기존 계정은 "아직 등록 안 됨(totp_enabled = 0)"으로 시작한다.
  if (version < 4) {
    db.exec(`
      BEGIN;
      ALTER TABLE users ADD COLUMN totp_secret TEXT;                         -- 인증 앱과 나눠 가진 비밀값(base32)
      ALTER TABLE users ADD COLUMN totp_enabled INTEGER NOT NULL DEFAULT 0;  -- 1 = 등록 완료
      ALTER TABLE users ADD COLUMN totp_last_step INTEGER;                   -- 마지막으로 통과한 코드의 30초 칸 번호(재사용 방지)
      ALTER TABLE users ADD COLUMN totp_failures INTEGER NOT NULL DEFAULT 0; -- 연속 실패 횟수
      ALTER TABLE users ADD COLUMN totp_locked_until INTEGER;                -- 이 시각(ms)까지 추가 인증 잠금
      PRAGMA user_version = 4;
      COMMIT;
    `);
  }

  // 5단계: 계정별 등록 기기. 서버는 공개키만 저장하고, 같은 기기인지는 공개키 지문(key_id)으로 판단한다.
  // name 은 사람이 읽는 이름표, reported_posture 는 기기가 주장하는 모의 보안 상태 — 둘 다 허용 판단에 쓰지 않는다.
  if (version < 5) {
    db.exec(`
      BEGIN;
      CREATE TABLE devices (
        id               TEXT PRIMARY KEY,                    -- 무작위 UUID
        user_id          INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        name             TEXT NOT NULL,
        key_id           TEXT NOT NULL,                       -- 공개키 SHA-256 지문
        public_key       TEXT NOT NULL,                       -- Ed25519 공개키(SPKI DER, base64url)
        status           TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'blocked')),
        reported_posture TEXT,
        created_at       INTEGER NOT NULL,                    -- 시각은 모두 ms
        expires_at       INTEGER NOT NULL,
        last_used_at     INTEGER,
        blocked_at       INTEGER,
        UNIQUE (user_id, key_id)
      );
      CREATE INDEX devices_user_id ON devices(user_id);
      PRAGMA user_version = 5;
      COMMIT;
    `);
  }
}

module.exports = { openDb };
