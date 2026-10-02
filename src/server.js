// 서버 실행 진입점: DB 파일을 열고 API를 127.0.0.1(내 컴퓨터 전용 주소)에서 연다
const fs = require('node:fs');
const path = require('node:path');
const { openDb } = require('./db');
const { createApp } = require('./app');

const PORT = Number(process.env.PORT ?? 3000);
const DB_FILE = process.env.DB_FILE ?? path.join(__dirname, '..', 'data', 'app.db');

fs.mkdirSync(path.dirname(DB_FILE), { recursive: true });
const db = openDb(DB_FILE);
const app = createApp({ db });

app.listen(PORT, '127.0.0.1', () => {
  console.log(`메모 API 실행 중: http://127.0.0.1:${PORT}  (종료: Ctrl + C)`);
});
