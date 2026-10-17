// パスワード生成。crypto.getRandomValues と棄却サンプリングで偏りのない乱数を使う。

export const CHARSETS = {
  lower: 'abcdefghijklmnopqrstuvwxyz',
  upper: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
  digits: '0123456789',
  symbols: '!@#$%^&*()-_=+[]{};:,.?/~',
};

export function randomInt(max) {
  const limit = Math.floor(0x1_0000_0000 / max) * max;
  const buf = new Uint32Array(1);
  for (;;) {
    crypto.getRandomValues(buf);
    if (buf[0] < limit) return buf[0] % max;
  }
}

export function generatePassword({ length = 20, lower = true, upper = true, digits = true, symbols = true } = {}) {
  const sets = Object.entries({ lower, upper, digits, symbols })
    .filter(([, on]) => on)
    .map(([name]) => CHARSETS[name]);
  if (sets.length === 0) throw new Error('文字の種類を1つ以上選んでください');
  if (length < sets.length) throw new Error('長さが短すぎます');
  const all = sets.join('');
  // 選んだ種類がすべて含まれるまで作り直す(偏りを生まない方法)
  for (;;) {
    let pw = '';
    for (let i = 0; i < length; i++) pw += all[randomInt(all.length)];
    if (sets.every((s) => [...pw].some((c) => s.includes(c)))) return pw;
  }
}

/** 文字の種類と長さから見たおおよそのエントロピー(ビット) */
export function estimateBits(pw) {
  let pool = 0;
  if (/[a-z]/.test(pw)) pool += 26;
  if (/[A-Z]/.test(pw)) pool += 26;
  if (/[0-9]/.test(pw)) pool += 10;
  if (/[^a-zA-Z0-9]/.test(pw)) pool += 33;
  return pool ? Math.round(pw.length * Math.log2(pool)) : 0;
}
