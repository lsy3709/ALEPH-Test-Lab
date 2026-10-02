// 2단계 검사: 비밀번호 해시 만들기·확인하기 (서버 없이 함수만 시험)
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { hashPassword, verifyPassword } = require('../src/passwords');

const FAKE_PASSWORD = 'lab-only-Pass-2026';

test('맞는 비밀번호는 true, 틀린 비밀번호는 false', async () => {
  const stored = await hashPassword(FAKE_PASSWORD);
  assert.equal(await verifyPassword(stored, FAKE_PASSWORD), true);
  assert.equal(await verifyPassword(stored, 'lab-only-Pass-2027'), false);
  assert.equal(await verifyPassword(stored, ''), false);
});

test('한글을 완성형·조합형 어느 쪽으로 입력해도 같은 비밀번호로 인정한다(NFKC 정규화)', async () => {
  const composed = '실습용비밀번호가나다2026';
  const decomposed = composed.normalize('NFD'); // 화면엔 같아 보여도 내부 코드가 다른 문자열
  assert.notEqual(composed, decomposed);

  const stored = await hashPassword(composed);
  assert.equal(await verifyPassword(stored, decomposed), true);
});

test('망가진 해시 값이 들어와도 서버가 멈추지 않고 false', async () => {
  assert.equal(await verifyPassword('not-a-hash', FAKE_PASSWORD), false);
  assert.equal(await verifyPassword(null, FAKE_PASSWORD), false);
});
