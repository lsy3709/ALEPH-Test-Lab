// 마이그레이션 검사: 이전 단계 DB를 열어도 기존 데이터가 그대로 남는다
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { DatabaseSync } = require('node:sqlite');
const { openDb } = require('../src/db');

test('1단계 DB의 메모를 보존한 채 사용자 표가 추가된다', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'memo-lab-'));
  const file = path.join(dir, 'step1.db');
  try {
    // 1단계 때 만들어진 DB를 그대로 흉내 낸다(메모 표만 있고 user_version = 1)
    const old = new DatabaseSync(file);
    old.exec(`
      CREATE TABLE memos (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        title      TEXT NOT NULL,
        body       TEXT NOT NULL DEFAULT '',
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
      );
      PRAGMA user_version = 1;
    `);
    old.prepare('INSERT INTO memos (title, body) VALUES (?, ?)').run('1단계 메모', '가짜 데이터');
    old.close();

    const db = openDb(file);
    const memo = db.prepare('SELECT title, body FROM memos').get();
    const { user_version: version } = db.prepare('PRAGMA user_version').get();
    const usersTable = db.prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'users'").get();
    db.close();

    assert.deepEqual({ ...memo }, { title: '1단계 메모', body: '가짜 데이터' });
    assert.ok(version >= 2);
    assert.ok(usersTable, 'users 표가 있어야 함');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
