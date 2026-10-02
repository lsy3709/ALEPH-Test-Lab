// 마이그레이션 검사: 이전 단계 DB를 열어도 기존 데이터가 그대로 남는다
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { DatabaseSync } = require('node:sqlite');
const { openDb } = require('../src/db');

const tableExists = (db, name) =>
  Boolean(db.prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?").get(name));

test('1단계 DB의 메모를 보존한 채 이후 단계 구조로 올라간다', () => {
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
    const memo = db.prepare('SELECT title, body, user_id FROM memos').get();
    const { user_version: version } = db.prepare('PRAGMA user_version').get();
    const hasUsers = tableExists(db, 'users');
    const hasSessions = tableExists(db, 'sessions');
    db.close();

    assert.deepEqual({ ...memo }, { title: '1단계 메모', body: '가짜 데이터', user_id: null });
    assert.ok(version >= 4);
    assert.ok(hasUsers, 'users 표가 있어야 함');
    assert.ok(hasSessions, 'sessions 표가 있어야 함');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('2단계 DB(계정 있음)를 열어도 계정과 비밀번호 해시가 그대로 남는다', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'memo-lab-'));
  const file = path.join(dir, 'step2.db');
  try {
    const old = new DatabaseSync(file);
    old.exec(`
      CREATE TABLE memos (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        title      TEXT NOT NULL,
        body       TEXT NOT NULL DEFAULT '',
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
      );
      CREATE TABLE users (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        email         TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        created_at    TEXT NOT NULL DEFAULT (datetime('now'))
      );
      PRAGMA user_version = 2;
    `);
    old.prepare('INSERT INTO users (email, password_hash) VALUES (?, ?)').run('student1@example.test', '$argon2id$fake-hash');
    old.prepare('INSERT INTO memos (title) VALUES (?)').run('2단계 메모');
    old.close();

    const db = openDb(file);
    const user = db.prepare('SELECT email, password_hash, totp_secret, totp_enabled FROM users').get();
    const memo = db.prepare('SELECT title, user_id FROM memos').get();
    db.close();

    // 계정·해시는 그대로, 추가 인증은 "아직 등록 안 됨"으로 시작한다
    assert.deepEqual(
      { ...user },
      { email: 'student1@example.test', password_hash: '$argon2id$fake-hash', totp_secret: null, totp_enabled: 0 },
    );
    assert.deepEqual({ ...memo }, { title: '2단계 메모', user_id: null });
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
