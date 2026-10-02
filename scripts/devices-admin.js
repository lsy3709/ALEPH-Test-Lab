// 개발용 관리 도구(서버 API가 아님) — 내 컴퓨터의 DB 파일을 직접 다룬다.
//   npm run devices-admin -- list                    등록 기기 목록(공개키는 보여 주지 않음)
//   npm run devices-admin -- expire <기기id 앞 8자>   [수업용 모의 조작] 30일이 지난 것처럼 만료시키기
// expire 는 만료 동작을 30일 기다리지 않고 확인하려는 실습용이다. 실제 서비스에는 이런 조작 경로가 없어야 한다.
const path = require('node:path');
const { openDb } = require('../src/db');
const { deviceState } = require('../src/devices');

const DB_FILE = process.env.DB_FILE ?? path.join(__dirname, '..', 'data', 'app.db');
const time = (ms) => (ms ? new Date(ms).toLocaleString('ko-KR') : '-');

function listDevices(db, now = Date.now()) {
  return db
    .prepare('SELECT d.*, u.email FROM devices d JOIN users u ON u.id = d.user_id ORDER BY u.email, d.created_at, d.rowid')
    .all()
    .map((d) => ({
      account: d.email,
      device: `${d.id.slice(0, 8)}…`,
      name: d.name,
      state: deviceState(d, now),
      expires: time(d.expires_at),
      lastUsed: time(d.last_used_at),
      mockPosture: d.reported_posture ?? '-',
    }));
}

function expireDevice(db, idPrefix, now = Date.now()) {
  if (!/^[0-9a-f]{8}$/.test(idPrefix ?? '')) throw new Error('기기 id 앞 8자(영문 소문자·숫자)를 넣으세요. 목록: npm run devices-admin -- list');
  const rows = db.prepare('SELECT id FROM devices WHERE substr(id, 1, 8) = ?').all(idPrefix);
  if (rows.length !== 1) throw new Error(`앞 8자가 ${idPrefix} 인 기기를 하나로 특정할 수 없습니다(${rows.length}개).`);
  db.prepare('UPDATE devices SET expires_at = ? WHERE id = ?').run(now - 1000, rows[0].id);
  return rows[0].id;
}

if (require.main === module) {
  const [command, arg] = process.argv.slice(2);
  const db = openDb(DB_FILE);
  try {
    if (command === 'list') {
      const rows = listDevices(db);
      console.log(`등록 기기: ${rows.length}대 (mockPosture 는 기기가 주장한 모의 값 — 서버는 믿지 않음)`);
      if (rows.length > 0) console.table(rows);
    } else if (command === 'expire') {
      const id = expireDevice(db, arg);
      console.log(`[모의 조작] 기기 ${id.slice(0, 8)}… 를 만료시켰습니다. 이 기기로 접속 중인 세션도 다음 요청부터 403 이 됩니다.`);
    } else {
      console.log('사용법: npm run devices-admin -- list  /  npm run devices-admin -- expire <기기id 앞 8자>');
      process.exitCode = 1;
    }
  } catch (err) {
    console.error(err.message);
    process.exitCode = 1;
  } finally {
    db.close();
  }
}

module.exports = { listDevices, expireDevice };
