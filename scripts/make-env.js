// 내 컴퓨터에 .env 파일을 만들고 SESSION_SECRET 에 무작위 비밀키를 넣는다.
// 비밀키 값은 화면에 출력하지 않는다. 이미 .env 가 있으면 덮어쓰지 않는다.
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const ENV_FILE = process.env.ENV_FILE ?? path.join(__dirname, '..', '.env');

if (fs.existsSync(ENV_FILE)) {
  const line = fs.readFileSync(ENV_FILE, 'utf8').split(/\r?\n/).find((l) => l.startsWith('SESSION_SECRET='));
  const length = line ? line.slice('SESSION_SECRET='.length).trim().length : 0;
  console.log(`.env 가 이미 있어 덮어쓰지 않았습니다. (SESSION_SECRET: ${length > 0 ? `${length}자` : '없음'})`);
  if (length < 32) {
    console.log('SESSION_SECRET 이 32자보다 짧습니다. .env 를 지우고 npm run setup 을 다시 실행하세요.');
    process.exitCode = 1;
  }
} else {
  const secret = crypto.randomBytes(32).toString('base64url'); // 무작위 32바이트 → 43자
  const content = [
    '# 이 파일은 내 컴퓨터에만 둔다(.gitignore 로 Git 에서 제외됨). 다른 사람에게 보내거나 붙여 넣지 말 것.',
    `SESSION_SECRET=${secret}`,
    '',
  ].join('\n');
  fs.writeFileSync(ENV_FILE, content, { flag: 'wx' }); // wx: 파일이 있으면 실패(실수로 덮어쓰기 방지)
  console.log(`.env 를 만들었습니다. (SESSION_SECRET: ${secret.length}자, 값은 출력하지 않음)`);
}
