// パスワード生成。crypto.getRandomValues と棄却サンプリングで偏りのない乱数を使う。

export const CHARSETS = {
  lower: 'abcdefghijklmnopqrstuvwxyz',
  upper: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
  digits: '0123456789',
  symbols: '!@#$%^&*()-_=+[]{};:,.?/~',
};

// 多くのサイトで使える記号だけ(「記号あり」用)
export const SAFE_SYMBOLS = '-_.!@#';

// 生成の型。おすすめ(英数字16文字)は記号や長さの制限があるサイトでもほぼ通り、約95ビットと十分強い
export const PRESETS = {
  standard: { length: 16, lower: true, upper: true, digits: true, symbols: 'none' },
  symbol: { length: 16, lower: true, upper: true, digits: true, symbols: 'safe' },
  short: { length: 12, lower: true, upper: true, digits: true, symbols: 'none' },
  pin: { length: 6, lower: false, upper: false, digits: true, symbols: 'none' },
};

/** 保存されていた設定などを安全な形にそろえる。使えなければ null */
export function normalizeOptions(o) {
  if (!o || typeof o !== 'object') return null;
  const length = Number.isInteger(o.length) ? Math.min(64, Math.max(4, o.length)) : 16;
  const symbols = ['none', 'safe', 'all'].includes(o.symbols) ? o.symbols : 'none';
  const out = { length, lower: o.lower === true, upper: o.upper === true, digits: o.digits === true, symbols };
  return out.lower || out.upper || out.digits || symbols !== 'none' ? out : null;
}

/** 設定がどの型と同じか(どれでもなければ null) */
export function presetOf(o) {
  const n = normalizeOptions(o);
  return n && (Object.keys(PRESETS).find((k) => Object.keys(n).every((f) => PRESETS[k][f] === n[f])) || null);
}

export function randomInt(max) {
  const limit = Math.floor(0x1_0000_0000 / max) * max;
  const buf = new Uint32Array(1);
  for (;;) {
    crypto.getRandomValues(buf);
    if (buf[0] < limit) return buf[0] % max;
  }
}

export function generatePassword(options = PRESETS.standard) {
  const { length, lower, upper, digits, symbols } = { ...PRESETS.standard, ...options };
  const symbolChars = symbols === 'safe' ? SAFE_SYMBOLS : symbols === 'all' ? CHARSETS.symbols : '';
  const sets = [lower && CHARSETS.lower, upper && CHARSETS.upper, digits && CHARSETS.digits, symbolChars].filter(Boolean);
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
