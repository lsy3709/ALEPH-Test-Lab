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

// Express 5 는 시작에 실패해도 이 함수를 부르고, 실패 이유를 err 로 넘겨 준다.
app.listen(PORT, '127.0.0.1', (err) => {
  if (err) {
    const reason =
      err.code === 'EADDRINUSE'
        ? `포트 ${PORT}번을 이미 다른 프로그램(예: 전에 켜 둔 서버)이 쓰고 있습니다. 그 창에서 Ctrl + C 로 끄고 다시 실행하세요.`
        : err.message;
    console.error(`서버를 시작하지 못했습니다: ${reason}`);
    process.exit(1);
  }
  console.log(`메모 API 실행 중: http://127.0.0.1:${PORT}  (종료: Ctrl + C)`);
});
