import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  createKey, seal, openWithPassword, openWithKey, WrongPasswordError, InvalidFileError, KDF_ITERATIONS,
} from '../js/crypto.js';
import { createVault, upsertEntry } from '../js/vault.js';

const PW = 'correct horse battery staple';

async function sample() {
  const keyInfo = await createKey(PW);
  const { vault } = upsertEntry(createVault(), { title: 'GitHub', username: 'me', password: 's3cret!' });
  return { keyInfo, vault, env: await seal(vault, keyInfo) };
}

test('暗号化して同じパスワードで復号できる', async () => {
  const { vault, env } = await sample();
  assert.equal(env.kdf.iterations, KDF_ITERATIONS);
  const opened = await openWithPassword(env, PW);
  assert.deepEqual(opened.vault, vault);
});

test('暗号文に平文が含まれない', async () => {
  const { env } = await sample();
  const text = JSON.stringify(env);
  assert.ok(!text.includes('s3cret'));
  assert.ok(!text.includes('GitHub'));
});

test('間違ったパスワードでは WrongPasswordError', async () => {
  const { env } = await sample();
  await assert.rejects(openWithPassword(env, 'wrong password!!'), WrongPasswordError);
});

test('暗号文の改ざんを検出する', async () => {
  const { env } = await sample();
  const bytes = Buffer.from(env.data, 'base64');
  bytes[0] ^= 1;
  await assert.rejects(openWithPassword({ ...env, data: bytes.toString('base64') }, PW), WrongPasswordError);
});

test('KDF設定の書き換えは拒否または検出する', async () => {
  const { env, keyInfo } = await sample();
  await assert.rejects(
    openWithPassword({ ...env, kdf: { ...env.kdf, iterations: 1000 } }, PW), InvalidFileError,
  );
  await assert.rejects(
    openWithKey({ ...env, kdf: { ...env.kdf, iterations: KDF_ITERATIONS + 1 } }, keyInfo), WrongPasswordError,
  );
});

test('保存のたびにIVが変わる', async () => {
  const { vault, keyInfo } = await sample();
  const a = await seal(vault, keyInfo);
  const b = await seal(vault, keyInfo);
  assert.notEqual(a.cipher.iv, b.cipher.iv);
  assert.notEqual(a.data, b.data);
});

test('kizupass 以外のファイルは InvalidFileError', async () => {
  await assert.rejects(openWithPassword({ foo: 1 }, PW), InvalidFileError);
  await assert.rejects(openWithPassword(null, PW), InvalidFileError);
});
