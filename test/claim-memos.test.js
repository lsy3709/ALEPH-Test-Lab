// 3단계 검사: 이전 단계에서 만든 "주인 없는 메모"를 실습 계정에 연결하는 개발용 도구
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { startTestServer, signup, loginFull } = require('./helpers');
const { assignOrphanMemos } = require('../scripts/claim-memos');

test('주인 없는 메모는 아무에게도 안 보이다가, 연결한 계정에게만 보인다', async () => {
  const srv = await startTestServer();
  try {
    srv.db.prepare('INSERT INTO memos (title, body) VALUES (?, ?)').run('옛 메모', '가짜 데이터'); // user_id = NULL
    await signup(srv.baseUrl, 'claimer@example.test');
    await signup(srv.baseUrl, 'bystander@example.test');
    const claimer = await loginFull(srv, 'claimer@example.test');
    const bystander = await loginFull(srv, 'bystander@example.test');

    assert.equal((await claimer.send('GET', '/memos')).json.memos.length, 0, '연결 전에는 안 보임');

    assert.equal(assignOrphanMemos(srv.db, 'claimer@example.test'), 1);
    const mine = await claimer.send('GET', '/memos');
    assert.deepEqual(
      mine.json.memos.map((m) => m.title),
      ['옛 메모'],
    );
    assert.equal((await bystander.send('GET', '/memos')).json.memos.length, 0, '다른 계정에는 안 보임');

    assert.equal(assignOrphanMemos(srv.db, 'claimer@example.test'), 0, '두 번 실행해도 추가로 바뀌는 것 없음');
    assert.throws(() => assignOrphanMemos(srv.db, 'nobody@example.test'), /없는 계정/);
  } finally {
    await srv.close();
  }
});
