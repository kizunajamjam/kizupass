// IndexedDB への保存。保存するのは暗号化済みの封筒だけ。

const DB_NAME = 'kizupass';
const STORE = 'kv';
const KEY = 'vault';

function open() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, 1);
    req.onupgradeneeded = () => req.result.createObjectStore(STORE);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
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

export const loadEnvelope = () => tx('readonly', (s) => s.get(KEY));
export const saveEnvelope = (env) => tx('readwrite', (s) => s.put(env, KEY));
export const clearAll = () => tx('readwrite', (s) => s.clear());

/** ブラウザに自動削除しないよう依頼する */
export async function requestPersist() {
  if (!navigator.storage?.persist) return false;
  return (await navigator.storage.persisted()) || navigator.storage.persist();
}
