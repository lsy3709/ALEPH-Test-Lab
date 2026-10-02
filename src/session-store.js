// 로그인 세션을 SQLite 의 sessions 표에 저장하는 보관함(express-session 의 Store 규칙을 따름)
// 세션 번호 생성·쿠키 서명은 express-session 라이브러리가 하고, 여기서는 "저장·조회·삭제"만 한다.
const session = require('express-session');

const DEFAULT_TTL_MS = 30 * 60 * 1000;

// 콜백을 다음 차례에 부른다(express-session 의 기본 보관함과 같은 방식)
function respond(cb, work) {
  let value;
  try {
    value = work();
  } catch (err) {
    if (cb) setImmediate(cb, err);
    return;
  }
  if (cb) setImmediate(cb, null, value);
}

class SqliteSessionStore extends session.Store {
  constructor(db, { ttlMs = DEFAULT_TTL_MS } = {}) {
    super();
    this.db = db;
    this.ttlMs = ttlMs;
  }

  // 쿠키 만료 시각을 그대로 서버 쪽 만료 시각으로 쓴다
  expiresAt(sess) {
    const time = sess?.cookie?.expires ? new Date(sess.cookie.expires).getTime() : NaN;
    return Number.isFinite(time) ? time : Date.now() + this.ttlMs;
  }

  // 세션 읽기: 없거나 만료됐으면 null(= 로그인 안 된 상태). 만료된 것은 바로 지운다.
  get(sid, cb) {
    respond(cb, () => {
      const row = this.db.prepare('SELECT sess, expires_at FROM sessions WHERE sid = ?').get(sid);
      if (!row) return null;
      if (row.expires_at <= Date.now()) {
        this.db.prepare('DELETE FROM sessions WHERE sid = ?').run(sid);
        return null;
      }
      return JSON.parse(row.sess);
    });
  }

  set(sid, sess, cb) {
    respond(cb, () => {
      this.db
        .prepare(
          `INSERT INTO sessions (sid, sess, expires_at) VALUES (?, ?, ?)
           ON CONFLICT(sid) DO UPDATE SET sess = excluded.sess, expires_at = excluded.expires_at`,
        )
        .run(sid, JSON.stringify(sess), this.expiresAt(sess));
    });
  }

  // 로그아웃·세션 교체 때 호출된다 → 서버에서 세션이 완전히 사라진다
  destroy(sid, cb) {
    respond(cb, () => {
      this.db.prepare('DELETE FROM sessions WHERE sid = ?').run(sid);
    });
  }

  // 요청이 올 때마다 만료 시각을 뒤로 미룬다(30분 동안 아무 요청이 없으면 만료)
  touch(sid, sess, cb) {
    respond(cb, () => {
      this.db.prepare('UPDATE sessions SET expires_at = ? WHERE sid = ?').run(this.expiresAt(sess), sid);
    });
  }

  // 만료된 세션 한꺼번에 지우기(서버가 주기적으로 호출). 지운 개수를 돌려준다.
  clearExpired() {
    return this.db.prepare('DELETE FROM sessions WHERE expires_at <= ?').run(Date.now()).changes;
  }
}

module.exports = { SqliteSessionStore };
