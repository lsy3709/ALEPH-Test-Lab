// 메모 API의 주소(라우트)와 처리 규칙
const express = require('express');
const { createAuthRouter } = require('./auth');

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

function createApp({ db }) {
  const app = express();
  app.disable('x-powered-by'); // 응답에 서버 종류(Express)를 드러내지 않음
  app.use(express.json({ limit: '10kb' })); // JSON 본문 해석, 너무 큰 요청은 거부

  app.get('/health', (req, res) => {
    res.json({ ok: true });
  });

  // 계정(가입 등) 주소는 auth.js 에 모아 둔다
  app.use('/auth', createAuthRouter({ db }));

  // 메모 목록
  app.get('/memos', (req, res) => {
    const memos = db.prepare(`SELECT ${MEMO_COLUMNS} FROM memos ORDER BY id`).all();
    res.json({ memos });
  });

  // 메모 만들기
  app.post('/memos', (req, res) => {
    const input = readMemoInput(req.body);
    if (!input) {
      return res.status(400).json({
        error: 'invalid_memo',
        message: `title(1~${MAX_TITLE}자)은 필수, body는 ${MAX_BODY}자 이하 문자열이어야 합니다.`,
      });
    }
    // ? 자리표시자: 입력값을 SQL 문장에 직접 이어 붙이지 않아 SQL 인젝션을 막는다.
    const result = db.prepare('INSERT INTO memos (title, body) VALUES (?, ?)').run(input.title, input.body);
    const memo = db.prepare(`SELECT ${MEMO_COLUMNS} FROM memos WHERE id = ?`).get(result.lastInsertRowid);
    res.status(201).json({ memo });
  });

  // 메모 하나 읽기
  app.get('/memos/:id', (req, res) => {
    const id = parseId(req.params.id);
    const memo = id && db.prepare(`SELECT ${MEMO_COLUMNS} FROM memos WHERE id = ?`).get(id);
    if (!memo) return res.status(404).json({ error: 'memo_not_found' });
    res.json({ memo });
  });

  // 메모 지우기
  app.delete('/memos/:id', (req, res) => {
    const id = parseId(req.params.id);
    const result = id && db.prepare('DELETE FROM memos WHERE id = ?').run(id);
    if (!result || result.changes === 0) return res.status(404).json({ error: 'memo_not_found' });
    res.status(204).end();
  });

  // 위 어디에도 해당하지 않는 주소
  app.use((req, res) => {
    res.status(404).json({ error: 'not_found' });
  });

  // 오류 처리: 잘못된 JSON 등은 400대, 그 밖의 예상 못 한 오류는 500. 내부 정보는 응답에 넣지 않는다.
  app.use((err, req, res, next) => {
    const status = Number.isInteger(err.status) && err.status >= 400 && err.status < 500 ? err.status : 500;
    if (status === 500) console.error(err);
    res.status(status).json({ error: status === 500 ? 'server_error' : 'bad_request' });
  });

  return app;
}

module.exports = { createApp };
