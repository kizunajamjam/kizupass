// Windows / Mac 向けの「ファイル1つ版」を作る。外部ツールは使わない。
// 画面・CSS・暗号ライブラリ・全 JS を1つの HTML に埋め込み、CSP で通信を一切禁止する。
//
// 使い方: node scripts/build-standalone.mjs <出力先.html> [version.json]

import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { dirname } from 'node:path';

const root = new URL('../', import.meta.url);
const read = (p) => readFile(new URL(p, root), 'utf8');
const sha256b64 = (s) => createHash('sha256').update(s, 'utf8').digest('base64');

// 依存される側から順に並べる
const MODULES = ['generator.js', 'vault.js', 'crypto.js', 'store.js', 'update.js', 'app.js'];

/** ES モジュールを、モジュール表 __kp に登録する関数スコープへ変換する */
function wrapModule(name, src) {
  const exported = [];
  let code = src.replace(
    /import\s*\{([^}]*)\}\s*from\s*'\.\/([\w.]+)';/g,
    (_, names, from) => {
      if (!MODULES.includes(from)) throw new Error(`${name}: 未知の import ${from}`);
      return `const {${names}} = __kp['${from}'];`;
    },
  );
  code = code.replace(/^export (async function|function|const|let|class) (\w+)/gm, (_, kind, id) => {
    exported.push(id);
    return `${kind} ${id}`;
  });
  if (/^\s*(import|export)\b/m.test(code)) throw new Error(`${name}: 変換できない import/export があります`);
  return `__kp['${name}'] = (() => {\n${code}\nreturn { ${exported.join(', ')} };\n})();\n`;
}

export async function buildStandalone(versionPath = 'version.json') {
  const info = JSON.parse(await readFile(versionPath.startsWith('/') ? versionPath : new URL(versionPath, root), 'utf8'));
  const build = { standalone: true, version: info.version, date: info.date || '' };

  const vendor = await read('js/vendor/argon2.umd.min.js');
  const css = await read('css/style.css');
  let app = `const __kp = {};\nglobalThis.KIZUPASS_BUILD = Object.freeze(${JSON.stringify(build)});\n`;
  for (const m of MODULES) app += wrapModule(m, await read(`js/${m}`));

  for (const [label, s] of [['vendor', vendor], ['app', app], ['css', css]]) {
    if (/<\/(script|style)/i.test(s) || s.includes('<!--')) throw new Error(`${label} に埋め込めない文字列があります`);
  }

  const icon = `data:image/svg+xml;base64,${Buffer.from(await read('icons/icon.svg')).toString('base64')}`;
  // ファイル版は通信を一切しない: connect-src などを指定せず default-src 'none' で全部禁止
  const csp = [
    "default-src 'none'",
    `script-src 'sha256-${sha256b64(vendor)}' 'sha256-${sha256b64(app)}' 'wasm-unsafe-eval'`,
    `style-src 'sha256-${sha256b64(css)}'`,
    'img-src data:',
    "base-uri 'none'",
    "form-action 'none'",
  ].join('; ');

  let html = await read('index.html');
  const swap = (pattern, replacement) => {
    if (!pattern.test(html)) throw new Error(`index.html に ${pattern} が見つかりません`);
    html = html.replace(pattern, () => replacement);
  };
  swap(/content="default-src[^"]*"/, `content="${csp}"`);
  swap(/\s*<link rel="manifest"[^>]*>/, '');
  swap(/<link rel="icon"[^>]*>/, `<link rel="icon" href="${icon}" type="image/svg+xml">`);
  swap(/\s*<link rel="apple-touch-icon"[^>]*>/, '');
  swap(/<link rel="stylesheet"[^>]*>/, `<style>${css}</style>`);
  swap(/<script src="js\/vendor\/argon2\.umd\.min\.js"><\/script>/, `<script>${vendor}</script>`);
  swap(/<script type="module" src="js\/app\.js"><\/script>/, `<script type="module">${app}</script>`);
  swap(/<title>kizupass<\/title>/, '<title>kizupass（ファイル版）</title>');

  if (/\s(src|href)="(?!data:|#)/.test(html)) throw new Error('外部ファイルへの参照が残っています');
  return { html, csp, build };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const out = process.argv[2];
  if (!out) throw new Error('出力先を指定してください');
  const { html, build } = await buildStandalone(process.argv[3]);
  await mkdir(dirname(out), { recursive: true });
  await writeFile(out, html);
  const hash = createHash('sha256').update(html).digest('hex');
  await writeFile(`${out}.sha256`, `${hash}  kizupass-offline.html\n`);
  console.log(`${out} (${build.version}, ${(html.length / 1024).toFixed(0)} KB) sha256=${hash}`);
}
