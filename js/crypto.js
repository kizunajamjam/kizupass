// 暗号化まわり。鍵の導出は Argon2id (同梱の hash-wasm)、暗号化は Web Crypto API の AES-256-GCM。
// 旧形式 (v1: PBKDF2) のファイルも読めるが、保存は常に v2 で行う。

const enc = new TextEncoder();
const dec = new TextDecoder();

export const FORMAT = 'kizupass';
export const VERSION = 2;
// OWASP 推奨の最低値 (19MiB, 2回) より強めの設定。iPhone でも1秒前後で終わる
export const ARGON2 = { memory: 65536, iterations: 3, parallelism: 1 }; // memory は KiB

// 細工されたファイルで弱すぎる設定や重すぎる設定を読み込まないための範囲
const LIMITS = {
  pbkdf2Iterations: [100_000, 10_000_000],
  argonMemory: [19_456, 1_048_576],
  argonIterations: [1, 10],
  argonParallelism: [1, 4],
};
const inRange = (v, [min, max]) => Number.isInteger(v) && v >= min && v <= max;

export class WrongPasswordError extends Error {
  constructor() {
    super('パスワードが違うか、ファイルが壊れています');
    this.name = 'WrongPasswordError';
  }
}

export class InvalidFileError extends Error {
  constructor(msg = 'kizupass のファイルではありません') {
    super(msg);
    this.name = 'InvalidFileError';
  }
}

export function toB64(bytes) {
  let s = '';
  const CHUNK = 0x8000;
  for (let i = 0; i < bytes.length; i += CHUNK) {
    s += String.fromCharCode(...bytes.subarray(i, i + CHUNK));
  }
  return btoa(s);
}

export function fromB64(str) {
  const s = atob(str);
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}

export function randomBytes(n) {
  return crypto.getRandomValues(new Uint8Array(n));
}

function argon2id() {
  const fn = globalThis.hashwasm?.argon2id;
  if (!fn) throw new Error('暗号ライブラリ (Argon2) を読み込めませんでした');
  return fn;
}

function checkKdf(kdf) {
  if (!kdf || typeof kdf.salt !== 'string') return false;
  let salt;
  try { salt = fromB64(kdf.salt); } catch { return false; }
  if (salt.length < 16) return false;
  if (kdf.name === 'Argon2id') {
    return inRange(kdf.memory, LIMITS.argonMemory)
      && inRange(kdf.iterations, LIMITS.argonIterations)
      && inRange(kdf.parallelism, LIMITS.argonParallelism);
  }
  if (kdf.name === 'PBKDF2') {
    return kdf.hash === 'SHA-256' && inRange(kdf.iterations, LIMITS.pbkdf2Iterations);
  }
  return false;
}

// 鍵導出の設定を決まった順序の文字列にする(追加認証データと同一判定に使う)
function canonicalKdf(kdf) {
  return kdf.name === 'Argon2id'
    ? `Argon2id:${kdf.memory}:${kdf.iterations}:${kdf.parallelism}:${kdf.salt}`
    : `PBKDF2:${kdf.hash}:${kdf.iterations}:${kdf.salt}`;
}

// ヘッダー(鍵導出の設定)を追加認証データにして、設定の改ざんも検出する
function aad(version, kdf) {
  return enc.encode(version === 1
    ? `${FORMAT}:v1:${kdf.iterations}:${kdf.salt}`
    : `${FORMAT}:v${version}:${canonicalKdf(kdf)}`);
}

export function sameKdf(a, b) {
  return !!a && !!b && canonicalKdf(a) === canonicalKdf(b);
}

export async function deriveKey(password, kdf) {
  const pw = enc.encode(password.normalize('NFC'));
  const salt = fromB64(kdf.salt);
  try {
    if (kdf.name === 'Argon2id') {
      const raw = await argon2id()({
        password: pw,
        salt,
        iterations: kdf.iterations,
        parallelism: kdf.parallelism,
        memorySize: kdf.memory,
        hashLength: 32,
        outputType: 'binary',
      });
      try {
        // エクスポート不可の鍵として取り込み、元のバイト列は消す
        return await crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt', 'decrypt']);
      } finally {
        raw.fill(0);
      }
    }
    const base = await crypto.subtle.importKey('raw', pw, 'PBKDF2', false, ['deriveKey']);
    return await crypto.subtle.deriveKey(
      { name: 'PBKDF2', hash: 'SHA-256', salt, iterations: kdf.iterations },
      base,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt'],
    );
  } finally {
    pw.fill(0);
  }
}

/** 新しい鍵を作る(初回設定・マスターパスワード変更・旧形式からの移行時) */
export async function createKey(password) {
  const kdf = { name: 'Argon2id', ...ARGON2, salt: toB64(randomBytes(16)) };
  return { key: await deriveKey(password, kdf), kdf };
}

/** 保管庫を暗号化して保存用の封筒(JSONにできるオブジェクト)にする。IVは毎回新しく作る */
export async function seal(vault, { key, kdf }) {
  const iv = randomBytes(12);
  const ct = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: aad(VERSION, kdf) },
    key,
    enc.encode(JSON.stringify(vault)),
  );
  return {
    format: FORMAT,
    version: VERSION,
    kdf: { ...kdf },
    cipher: { name: 'AES-GCM', iv: toB64(iv) },
    data: toB64(new Uint8Array(ct)),
  };
}

function checkEnvelope(env) {
  if (!env || typeof env !== 'object' || env.format !== FORMAT) throw new InvalidFileError();
  if (env.version !== 1 && env.version !== 2) {
    throw new InvalidFileError('このバージョンのファイルには対応していません');
  }
  if (!checkKdf(env.kdf) || (env.version === 1 && env.kdf.name !== 'PBKDF2')
      || !env.cipher || env.cipher.name !== 'AES-GCM' || typeof env.cipher.iv !== 'string'
      || typeof env.data !== 'string') {
    throw new InvalidFileError();
  }
}

/** 既に導出済みの鍵で開く */
export async function openWithKey(env, keyInfo) {
  checkEnvelope(env);
  let pt;
  try {
    pt = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: fromB64(env.cipher.iv), additionalData: aad(env.version, env.kdf) },
      keyInfo.key,
      fromB64(env.data),
    );
  } catch {
    throw new WrongPasswordError();
  }
  return JSON.parse(dec.decode(pt));
}

/** パスワードで開く。成功すると保管庫と鍵情報を返す */
export async function openWithPassword(env, password) {
  checkEnvelope(env);
  const kdf = { ...env.kdf };
  const keyInfo = { key: await deriveKey(password, kdf), kdf };
  const vault = await openWithKey(env, keyInfo);
  return { vault, keyInfo };
}

/** 旧方式(PBKDF2)の鍵なら Argon2id へ移行すべきか */
export function needsUpgrade(keyInfo) {
  return keyInfo.kdf.name !== 'Argon2id'
    || keyInfo.kdf.memory < ARGON2.memory
    || keyInfo.kdf.iterations < ARGON2.iterations;
}
