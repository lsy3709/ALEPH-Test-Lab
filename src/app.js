// 앱 조립: 공통 설정 → 세션 → 계정 주소 → (로그인 확인 후) 메모 주소 → 404·오류 처리
const express = require('express');
const session = require('express-session');
const { createAuthRouter, requireLogin } = require('./auth');
const { createMemosRouter } = require('./memos');
const { SqliteSessionStore } = require('./session-store');

const SESSION_COOKIE = 'memo.sid';
const SESSION_IDLE_MS = 30 * 60 * 1000; // 30분 동안 요청이 없으면 로그인 만료
const MIN_SECRET_LENGTH = 32;

// sessionSecret: 세션 쿠키 서명용 비밀키(.env 의 SESSION_SECRET). 쿠키를 위조하지 못하게 한다.
// loginRateLimit: 로그인 시도 제한 설정(테스트에서 바꿔 쓸 수 있음)
function createApp({ db, sessionSecret, loginRateLimit } = {}) {
  if (typeof sessionSecret !== 'string' || sessionSecret.length < MIN_SECRET_LENGTH) {
    throw new Error(`SESSION_SECRET 은 ${MIN_SECRET_LENGTH}자 이상이어야 합니다.`);
  }

  const app = express();
  app.disable('x-powered-by'); // 응답에 서버 종류(Express)를 드러내지 않음
  app.use(express.json({ limit: '10kb' })); // JSON 본문만 해석, 너무 큰 요청은 거부

  const sessionStore = new SqliteSessionStore(db, { ttlMs: SESSION_IDLE_MS });
  app.locals.sessionStore = sessionStore; // server.js 가 만료 세션 정리에 쓴다
  app.use(
    session({
      name: SESSION_COOKIE,
      secret: sessionSecret,
      store: sessionStore,
      resave: false,
      saveUninitialized: false, // 로그인하기 전에는 세션·쿠키를 만들지 않는다
      rolling: true, // 요청할 때마다 만료 시각을 30분 뒤로 미룬다
      cookie: {
        httpOnly: true, // 웹페이지의 자바스크립트가 쿠키를 읽지 못하게
        sameSite: 'strict', // 다른 사이트에서 보낸 요청에는 쿠키를 붙이지 않게
        secure: 'auto', // HTTPS 로 접속하면 Secure 쿠키(지금은 내 컴퓨터 http 라서 붙지 않음)
        maxAge: SESSION_IDLE_MS,
        path: '/',
      },
    }),
  );

  app.get('/health', (req, res) => {
    res.json({ ok: true });
  });

  // 계정(가입·로그인·로그아웃·내 정보) 주소는 auth.js 에 모아 둔다
  app.use('/auth', createAuthRouter({ db, cookieName: SESSION_COOKIE, loginRateLimit }));

  // 메모 주소는 문지기(requireLogin)를 먼저 통과해야 들어갈 수 있다
  app.use('/memos', requireLogin(db), createMemosRouter({ db }));

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
