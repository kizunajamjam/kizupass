// 暗号化済みの封筒だけを保存する。IndexedDB が使えない環境(ファイル版を開いた一部のブラウザなど)では localStorage を使う。

const DB_NAME = 'kizupass';
const STORE = 'kv';
const KEY = 'vault';
const LS_KEY = 'kizupass:vault';

function open() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, 1);
    req.onupgradeneeded = () => req.result.createObjectStore(STORE);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
    // 応答が返ってこない環境もあるので打ち切る
    setTimeout(() => reject(new Error('IndexedDB timeout')), 3000);
  });
}

async function tx(mode, fn) {
  const db = await open();
  try {
    return await new Promise((resolve, reject) => {
      const t = db.transaction(STORE, mode);
      const req = fn(t.objectStore(STORE));
      t.oncomplete = () => resolve(req.result);
      t.onerror = () => reject(t.error);
      t.onabort = () => reject(t.error);
    });
  } finally {
    db.close();
  }
}

let backend = null;
async function useIdb() {
  if (backend === null) {
    try {
      (await open()).close();
      backend = 'idb';
    } catch {
      backend = 'local';
    }
  }
  return backend === 'idb';
}

export async function loadEnvelope() {
  if (await useIdb()) return tx('readonly', (s) => s.get(KEY));
  const s = localStorage.getItem(LS_KEY);
  return s ? JSON.parse(s) : undefined;
}

export async function saveEnvelope(env) {
  if (await useIdb()) return tx('readwrite', (s) => s.put(env, KEY));
  return localStorage.setItem(LS_KEY, JSON.stringify(env));
}

export async function clearAll() {
  if (await useIdb()) return tx('readwrite', (s) => s.clear());
  return localStorage.removeItem(LS_KEY);
}

/** ブラウザに自動削除しないよう依頼する */
export async function requestPersist() {
  if (!navigator.storage?.persist) return false;
  return (await navigator.storage.persisted()) || navigator.storage.persist();
}
