import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import vm from 'node:vm';
import { buildStandalone } from '../scripts/build-standalone.mjs';

const { html, csp } = await buildStandalone();
const blocks = (tag) => [...html.matchAll(new RegExp(`<${tag}[^>]*>([\\s\\S]*?)</${tag}>`, 'g'))].map((m) => m[1]);
const hash = (s) => `'sha256-${createHash('sha256').update(s, 'utf8').digest('base64')}'`;

test('ファイル版は外部ファイルを一切参照しない', () => {
  assert.doesNotMatch(html, /\s(src|href)="(?!data:|#)/);
  // 許可するのはライブラリのライセンス表記と、入力されたURLに https:// を補う処理だけ
  const urls = [...html.matchAll(/https?:\/\/[^\s'"`)]*/g)].map((m) => m[0]);
  assert.deepEqual(urls, ['https://www.npmjs.com/package/hash-wasm', 'https://${url}']);
});

test('CSP で通信を全面禁止し、埋め込みスクリプトはハッシュで許可する', () => {
  assert.match(csp, /^default-src 'none';/);
  assert.doesNotMatch(csp, /connect-src|'unsafe-inline'|'unsafe-eval'[^-]/);
  const scripts = blocks('script');
  assert.equal(scripts.length, 2);
  for (const s of scripts) assert.ok(csp.includes(hash(s)), 'script のハッシュが CSP にある');
  for (const s of blocks('style')) assert.ok(csp.includes(hash(s)), 'style のハッシュが CSP にある');
});

test('埋め込んだ JavaScript が構文として正しい', () => {
  for (const s of blocks('script')) assert.doesNotThrow(() => new vm.Script(s));
});
