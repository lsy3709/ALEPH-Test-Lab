// 메모 주소(/memos/...): 로그인한 사용자 "자신의" 메모만 다룬다
// 모든 SQL 에 user_id = 지금 로그인한 사람 조건을 붙여, 주소의 id 를 바꿔도 남의 메모에 닿지 않게 한다.
const express = require('express');

const MEMO_COLUMNS = 'id, title, body, created_at AS createdAt';
const MAX_TITLE = 100;
const MAX_BODY = 2000;

// 주소의 :id 가 양의 정수일 때만 숫자로 바꾼다. 그 외('abc', '-1', '1.5')는 null.
function parseId(raw) {
  return /^[1-9]\d{0,9}$/.test(raw) ? Number(raw) : null;
}

// 요청 본문에서 메모 입력값을 꺼내 검사한다. 문제가 있으면 null.
function readMemoInput(body) {
  const title = typeof body?.title === 'string' ? body.title.trim() : '';
  const text = body?.body === undefined ? '' : body.body;
  if (!title || title.length > MAX_TITLE) return null;
  if (typeof text !== 'string' || text.length > MAX_BODY) return null;
  return { title, body: text };
}

// req.user 는 앞단의 requireLogin 문지기가 서버 세션을 확인하고 넣어 준 값이다.
function createMemosRouter({ db }) {
  const router = express.Router();

  // 내 메모 목록
  router.get('/', (req, res) => {
    const memos = db.prepare(`SELECT ${MEMO_COLUMNS} FROM memos WHERE user_id = ? ORDER BY id`).all(req.user.id);
    res.json({ memos });
  });

  // 메모 만들기(주인 = 지금 로그인한 사람)
  router.post('/', (req, res) => {
    const input = readMemoInput(req.body);
    if (!input) {
      return res.status(400).json({
        error: 'invalid_memo',
        message: `title(1~${MAX_TITLE}자)은 필수, body는 ${MAX_BODY}자 이하 문자열이어야 합니다.`,
      });
    }
    // ? 자리표시자: 입력값을 SQL 문장에 직접 이어 붙이지 않아 SQL 인젝션을 막는다.
    const result = db
      .prepare('INSERT INTO memos (user_id, title, body) VALUES (?, ?, ?)')
      .run(req.user.id, input.title, input.body);
    const memo = db.prepare(`SELECT ${MEMO_COLUMNS} FROM memos WHERE id = ?`).get(result.lastInsertRowid);
    res.status(201).json({ memo });
  });

  // 내 메모 하나 읽기 — 남의 메모면 "없음(404)"으로 답해 존재 여부도 숨긴다
  router.get('/:id', (req, res) => {
    const id = parseId(req.params.id);
    const memo = id && db.prepare(`SELECT ${MEMO_COLUMNS} FROM memos WHERE id = ? AND user_id = ?`).get(id, req.user.id);
    if (!memo) return res.status(404).json({ error: 'memo_not_found' });
    res.json({ memo });
  });

  // 내 메모 지우기
  router.delete('/:id', (req, res) => {
    const id = parseId(req.params.id);
    const result = id && db.prepare('DELETE FROM memos WHERE id = ? AND user_id = ?').run(id, req.user.id);
    if (!result || result.changes === 0) return res.status(404).json({ error: 'memo_not_found' });
    res.status(204).end();
  });

  return router;
}

module.exports = { createMemosRouter };
