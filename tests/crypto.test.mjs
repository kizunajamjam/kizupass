import './setup.mjs';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  createKey, seal, openWithPassword, openWithKey, sameKdf, needsUpgrade, toB64, randomBytes,
  WrongPasswordError, InvalidFileError, ARGON2,
} from '../js/crypto.js';
import { createVault, upsertEntry } from '../js/vault.js';

const PW = 'correct horse battery staple';

async function sample() {
  const keyInfo = await createKey(PW);
  const { vault } = upsertEntry(createVault(), { title: 'GitHub', username: 'me', password: 's3cret!' });
  return { keyInfo, vault, env: await seal(vault, keyInfo) };
}

/** 初版 (v1: PBKDF2) と同じ形式のファイルを作る */
async function sealV1(vault, password, iterations = 600_000) {
  const enc = new TextEncoder();
  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const base = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']);
  const key = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', hash: 'SHA-256', salt, iterations }, base,
    { name: 'AES-GCM', length: 256 }, false, ['encrypt'],
  );
  const saltB64 = toB64(salt);
  const ct = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: enc.encode(`kizupass:v1:${iterations}:${saltB64}`) },
    key, enc.encode(JSON.stringify(vault)),
  );
  return {
    format: 'kizupass',
    version: 1,
    kdf: { name: 'PBKDF2', hash: 'SHA-256', iterations, salt: saltB64 },
    cipher: { name: 'AES-GCM', iv: toB64(iv) },
    data: toB64(new Uint8Array(ct)),
  };
}

test('Argon2id の計算結果が参照実装 (argon2-cffi) と一致する', async () => {
  const hex = await globalThis.hashwasm.argon2id({
    password: 'password', salt: 'somesalt', iterations: 2, parallelism: 4,
    memorySize: 65536, hashLength: 32, outputType: 'hex',
  });
  assert.equal(hex, '1a9677b0afe81fda7b548895e7a1bfeb8668ffc19a530e37e088a668fab1c02a');
});

test('Argon2id で暗号化して同じパスワードで復号できる', async () => {
  const { vault, env } = await sample();
  assert.equal(env.version, 2);
  assert.deepEqual(
    { name: env.kdf.name, memory: env.kdf.memory, iterations: env.kdf.iterations, parallelism: env.kdf.parallelism },
    { name: 'Argon2id', ...ARGON2 },
  );
  const opened = await openWithPassword(env, PW);
  assert.deepEqual(opened.vault, vault);
  assert.equal(needsUpgrade(opened.keyInfo), false);
  assert.ok(sameKdf(opened.keyInfo.kdf, env.kdf));
});

test('鍵はエクスポートできない', async () => {
  const { keyInfo } = await sample();
  assert.equal(keyInfo.key.extractable, false);
  await assert.rejects(crypto.subtle.exportKey('raw', keyInfo.key));
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

test('鍵導出の設定の書き換えは拒否または検出する', async () => {
  const { env, keyInfo } = await sample();
  // 弱すぎる設定は読み込まない
  await assert.rejects(openWithPassword({ ...env, kdf: { ...env.kdf, memory: 1024 } }, PW), InvalidFileError);
  await assert.rejects(openWithPassword({ ...env, kdf: { ...env.kdf, iterations: 0 } }, PW), InvalidFileError);
  // 重すぎる設定も読み込まない
  await assert.rejects(openWithPassword({ ...env, kdf: { ...env.kdf, memory: 4_194_304 } }, PW), InvalidFileError);
  // 範囲内の書き換えは追加認証データで検出する
  await assert.rejects(openWithKey({ ...env, kdf: { ...env.kdf, iterations: 4 } }, keyInfo), WrongPasswordError);
  // v1 を名乗って v2 を読ませることはできない
  await assert.rejects(openWithPassword({ ...env, version: 1 }, PW), InvalidFileError);
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
  await assert.rejects(openWithPassword({ format: 'kizupass', version: 3 }, PW), InvalidFileError);
});

test('初版 (v1: PBKDF2) のファイルも開けて、移行対象と判定される', async () => {
  const { vault } = upsertEntry(createVault(), { title: 'old', password: 'p' });
  const v1 = await sealV1(vault, PW);
  const opened = await openWithPassword(v1, PW);
  assert.deepEqual(opened.vault, vault);
  assert.equal(needsUpgrade(opened.keyInfo), true);
  await assert.rejects(openWithPassword(v1, 'wrong password!!'), WrongPasswordError);

  // 移行: 新しい鍵で保存し直すと Argon2id の v2 になる
  const upgraded = await seal(opened.vault, await createKey(PW));
  assert.equal(upgraded.version, 2);
  assert.equal(upgraded.kdf.name, 'Argon2id');
  assert.deepEqual((await openWithPassword(upgraded, PW)).vault, vault);
});
