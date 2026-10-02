// express-session 의 콜백 함수를 await 로 쓸 수 있게 감싼 도우미

// 세션 번호를 새로 발급한다(이전 번호의 서버 세션은 지워짐). 권한이 바뀌는 순간(로그인·추가 인증)에 쓴다.
const regenerateSession = (req) =>
  new Promise((resolve, reject) => req.session.regenerate((err) => (err ? reject(err) : resolve())));

// 바뀐 세션 내용을 서버 저장소에 지금 바로 저장한다
const saveSession = (req) =>
  new Promise((resolve, reject) => req.session.save((err) => (err ? reject(err) : resolve())));

module.exports = { regenerateSession, saveSession };
