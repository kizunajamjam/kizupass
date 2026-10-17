import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';

// 同梱ライブラリが勝手に書き換えられていないことを確認する。
// hash-wasm 4.12.0 (npm, sha512-+/2B2rYLb48I/evdOIhP+K/DD2ca2fgBjp6O+GBEnCDk2e4rpeXIK8GvIyRPjTezgmWn9gmKwkQjjx6BtqDHVQ==)
// の dist/argon2.umd.min.js。更新するときは README の手順に従ってこの値も変える。
const EXPECTED = {
  'js/vendor/argon2.umd.min.js': 'dcec617a2e1b700fa132d1583a186cb70611113395e869f2dd6cc82b415d3094',
};

test('同梱ライブラリのハッシュが記録と一致する', async () => {
  for (const [path, sha256] of Object.entries(EXPECTED)) {
    const data = await readFile(new URL(`../${path}`, import.meta.url));
    assert.equal(createHash('sha256').update(data).digest('hex'), sha256, path);
  }
});

test('同梱ライブラリは通信や eval をしない', async () => {
  const src = await readFile(new URL('../js/vendor/argon2.umd.min.js', import.meta.url), 'utf8');
  for (const word of ['fetch(', 'XMLHttpRequest', 'WebSocket', 'eval(', 'new Function', 'importScripts']) {
    assert.ok(!src.includes(word), word);
  }
});

test('version.json の配信ファイル一覧がすべて存在する', async () => {
  const info = JSON.parse(await readFile(new URL('../version.json', import.meta.url), 'utf8'));
  for (const p of info.assets) await readFile(new URL(`../${p}`, import.meta.url));
});
