// 暗号化まわり。Web Crypto API のみを使い、外部ライブラリには依存しない。
// 方式: PBKDF2-SHA256 (600,000回) で鍵を導出 → AES-256-GCM で保管庫全体を暗号化。

const enc = new TextEncoder();
const dec = new TextDecoder();

export const FORMAT = 'kizupass';
export const VERSION = 1;
export const KDF_ITERATIONS = 600_000;
// 細工されたファイルで弱い設定や極端に重い設定を読み込まないための範囲
const MIN_ITERATIONS = 100_000;
const MAX_ITERATIONS = 10_000_000;

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

export async function deriveKey(password, salt, iterations = KDF_ITERATIONS) {
  const base = await crypto.subtle.importKey(
    'raw', enc.encode(password.normalize('NFC')), 'PBKDF2', false, ['deriveKey'],
  );
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', hash: 'SHA-256', salt, iterations },
    base,
    { name: 'AES-GCM', length: 256 },
    false, // 鍵はエクスポート不可
    ['encrypt', 'decrypt'],
  );
}

// ヘッダー(KDF設定)を追加認証データにして、設定の改ざんも検出する
function aad(iterations, saltB64) {
  return enc.encode(`${FORMAT}:v${VERSION}:${iterations}:${saltB64}`);
}

/** 新しい鍵を作る(初回設定・マスターパスワード変更時) */
export async function createKey(password) {
  const salt = randomBytes(16);
  const key = await deriveKey(password, salt, KDF_ITERATIONS);
  return { key, salt, iterations: KDF_ITERATIONS };
}

/** 保管庫を暗号化して保存用の封筒(JSONにできるオブジェクト)にする。IVは毎回新しく作る */
export async function seal(vault, { key, salt, iterations }) {
  const iv = randomBytes(12);
  const saltB64 = toB64(salt);
  const ct = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: aad(iterations, saltB64) },
    key,
    enc.encode(JSON.stringify(vault)),
  );
  return {
    format: FORMAT,
    version: VERSION,
    kdf: { name: 'PBKDF2', hash: 'SHA-256', iterations, salt: saltB64 },
    cipher: { name: 'AES-GCM', iv: toB64(iv) },
    data: toB64(new Uint8Array(ct)),
  };
}

function checkEnvelope(env) {
  if (!env || typeof env !== 'object' || env.format !== FORMAT) throw new InvalidFileError();
  if (env.version !== VERSION) throw new InvalidFileError('このバージョンのファイルには対応していません');
  const { kdf, cipher } = env;
  if (!kdf || kdf.name !== 'PBKDF2' || kdf.hash !== 'SHA-256' || typeof kdf.salt !== 'string'
      || !Number.isInteger(kdf.iterations)
      || kdf.iterations < MIN_ITERATIONS || kdf.iterations > MAX_ITERATIONS
      || !cipher || cipher.name !== 'AES-GCM' || typeof cipher.iv !== 'string'
      || typeof env.data !== 'string') {
    throw new InvalidFileError();
  }
}

/** 封筒の鍵情報(ソルト・反復回数)を取り出す */
export function envelopeParams(env) {
  checkEnvelope(env);
  return { salt: fromB64(env.kdf.salt), iterations: env.kdf.iterations };
}

/** 既に導出済みの鍵で開く */
export async function openWithKey(env, keyInfo) {
  checkEnvelope(env);
  let pt;
  try {
    pt = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: fromB64(env.cipher.iv), additionalData: aad(env.kdf.iterations, env.kdf.salt) },
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
  const { salt, iterations } = envelopeParams(env);
  const key = await deriveKey(password, salt, iterations);
  const keyInfo = { key, salt, iterations };
  const vault = await openWithKey(env, keyInfo);
  return { vault, keyInfo };
}
