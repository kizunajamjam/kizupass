import { test } from 'node:test';
import assert from 'node:assert/strict';
import { toCsv, normalizeUrl } from '../js/csv.js';

const entry = (o) => ({ title: '', username: '', password: '', url: '', notes: '', ...o });

/** RFC 4180 の簡易パーサ(テストで書き出し結果を読み戻すため) */
function parse(csv) {
  const rows = [];
  let row = [];
  let cur = '';
  let q = false;
  for (let i = 0; i < csv.length; i++) {
    const c = csv[i];
    if (q) {
      if (c === '"' && csv[i + 1] === '"') { cur += '"'; i++; } else if (c === '"') q = false; else cur += c;
    } else if (c === '"') q = true;
    else if (c === ',') { row.push(cur); cur = ''; } else if (c === '\n') { row.push(cur); rows.push(row); row = []; cur = ''; } else cur += c;
  }
  return rows;
}

test('URL をそろえる', () => {
  assert.equal(normalizeUrl('amazon.co.jp'), 'https://amazon.co.jp/');
  assert.equal(normalizeUrl(' https://github.com/login '), 'https://github.com/login');
  assert.equal(normalizeUrl('http://example.com'), 'http://example.com/');
  assert.equal(normalizeUrl(''), '');
  assert.equal(normalizeUrl('javascript:alert(1)'), '');
  assert.equal(normalizeUrl('ftp://example.com'), '');
  assert.equal(normalizeUrl('メモ'), '');
});

test('Apple 形式と Chrome 形式の見出し', () => {
  const e = [entry({ title: 'A', url: 'a.com', username: 'u', password: 'p', notes: 'n' })];
  assert.deepEqual(parse(toCsv(e, 'apple').csv), [
    ['Title', 'URL', 'Username', 'Password', 'Notes', 'OTPAuth'],
    ['A', 'https://a.com/', 'u', 'p', 'n', ''],
  ]);
  assert.deepEqual(parse(toCsv(e, 'chrome').csv), [
    ['name', 'url', 'username', 'password', 'note'],
    ['A', 'https://a.com/', 'u', 'p', 'n'],
  ]);
});

test('カンマ・引用符・改行・前後の空白を含んでも元に戻せる', () => {
  const tricky = entry({
    title: 'Bank, "main"', url: 'bank.example.jp', username: ' me ', password: 'a"b,c\nd', notes: '1行目\r\n2行目',
  });
  const [, row] = parse(toCsv([tricky], 'chrome').csv);
  assert.deepEqual(row, ['Bank, "main"', 'https://bank.example.jp/', ' me ', 'a"b,c\nd', '1行目\r\n2行目']);
});

test('URL がない項目は含めず、名前を返す', () => {
  const r = toCsv([entry({ title: 'WiFi' }), entry({ title: 'X', url: 'x.com' }), entry({ url: 'メモ' })], 'apple');
  assert.equal(r.count, 1);
  assert.deepEqual(r.skipped, ['WiFi', '(無題)']);
  assert.throws(() => toCsv([], 'unknown'));
});
