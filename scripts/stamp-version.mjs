// 公開用に version.json へバージョン(コミット)情報を書き込む。CI から呼ぶ
// 使い方: node scripts/stamp-version.mjs <出力先 version.json>
import { readFile, writeFile } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';

const out = process.argv[2];
if (!out) throw new Error('出力先を指定してください');
const git = (...args) => execFileSync('git', args, { encoding: 'utf8' }).trim();

const info = JSON.parse(await readFile(new URL('../version.json', import.meta.url), 'utf8'));
const sha = git('rev-parse', 'HEAD');
const repo = process.env.GITHUB_REPOSITORY;
info.version = sha.slice(0, 7);
info.date = git('log', '-1', '--format=%cd', '--date=format:%Y-%m-%d %H:%M');
info.message = git('log', '-1', '--format=%s').slice(0, 200);
info.commitUrl = repo ? `https://github.com/${repo}/commit/${sha}` : '';
await writeFile(out, `${JSON.stringify(info, null, 2)}\n`);
console.log(`version ${info.version}: ${info.message}`);
