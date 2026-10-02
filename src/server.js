// 서버 실행 진입점: 비밀키 확인 → DB 파일 열기 → API를 127.0.0.1(내 컴퓨터 전용 주소)에서 연다
const fs = require('node:fs');
const path = require('node:path');
const { openDb } = require('./db');
const { createApp } = require('./app');

const PORT = Number(process.env.PORT ?? 3000);
const DB_FILE = process.env.DB_FILE ?? path.join(__dirname, '..', 'data', 'app.db');
const SESSION_SECRET = process.env.SESSION_SECRET; // .env 파일에서 읽음(npm start 가 --env-file=.env 로 불러옴)
const CLEANUP_INTERVAL_MS = 10 * 60 * 1000;

// 비밀키가 없으면 "아무 값으로나" 시작하지 않고 멈춘다
if (typeof SESSION_SECRET !== 'string' || SESSION_SECRET.length < 32) {
  console.error('SESSION_SECRET 이 없거나 32자보다 짧습니다. 먼저 npm run setup 을 실행하세요.');
  process.exit(1);
}

fs.mkdirSync(path.dirname(DB_FILE), { recursive: true });
const db = openDb(DB_FILE);
const app = createApp({ db, sessionSecret: SESSION_SECRET });

// 만료된 세션 정리: 시작할 때 한 번, 그 뒤 10분마다
const { sessionStore } = app.locals;
sessionStore.clearExpired();
setInterval(() => sessionStore.clearExpired(), CLEANUP_INTERVAL_MS).unref();

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
