// 他のパスワード管理 (Apple「パスワード」/ Google Chrome) へ移すための CSV 書き出し。
// 出力は暗号化されないので、呼び出し側で必ず警告と確認を行うこと。

export const CSV_FORMATS = {
  // Safari / 「パスワード」アプリが書き出すのと同じ列
  apple: {
    header: ['Title', 'URL', 'Username', 'Password', 'Notes', 'OTPAuth'],
    row: (e, url) => [e.title, url, e.username, e.password, e.notes, ''],
  },
  // Chrome のパスワードマネージャーが書き出すのと同じ列
  chrome: {
    header: ['name', 'url', 'username', 'password', 'note'],
    row: (e, url) => [e.title, url, e.username, e.password, e.notes],
  },
};

/** 読み込み先が受け付ける http(s) の URL にそろえる。使えなければ空文字 */
export function normalizeUrl(raw) {
  let s = (raw || '').trim();
  if (!s) return '';
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) s = `https://${s}`;
  try {
    const u = new URL(s);
    return (u.protocol === 'https:' || u.protocol === 'http:') && u.hostname.includes('.') ? u.href : '';
  } catch {
    return '';
  }
}

function field(v) {
  const s = String(v ?? '');
  return /[",\r\n]/.test(s) || s !== s.trim() ? `"${s.replace(/"/g, '""')}"` : s;
}

/**
 * CSV を作る。URL がない項目は読み込み先で拒否されるため含めず、skipped で返す。
 * @returns {{ csv: string, count: number, skipped: string[] }}
 */
export function toCsv(entries, format) {
  const f = CSV_FORMATS[format];
  if (!f) throw new Error(`未対応の形式です: ${format}`);
  const lines = [f.header.map(field).join(',')];
  const skipped = [];
  for (const e of entries) {
    const url = normalizeUrl(e.url);
    if (!url) {
      skipped.push(e.title || '(無題)');
      continue;
    }
    lines.push(f.row(e, url).map(field).join(','));
  }
  return { csv: `${lines.join('\n')}\n`, count: lines.length - 1, skipped };
}
