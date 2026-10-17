// アプリ本体をキャッシュし、利用者が「更新」を押すまで同じバージョンを使い続ける。
// サーバー上のファイルが書き換えられても、確認なしには読み込まれない。
//
// - pinned: いま使っているバージョンのキャッシュ
// - staged: ダウンロード済みで、適用待ちの新しいバージョン
// 外部への通信は一切しない。

const META = 'kizupass-meta';
const url = (p) => new URL(p, self.registration.scope).href;

async function getMeta(key) {
  const res = await (await caches.open(META)).match(url(`__${key}`));
  return res ? res.json() : null;
}

async function setMeta(key, value) {
  const cache = await caches.open(META);
  if (value === null) await cache.delete(url(`__${key}`));
  else await cache.put(url(`__${key}`), new Response(JSON.stringify(value)));
}

async function fetchManifest() {
  const res = await fetch(url('version.json'), { cache: 'no-store' });
  if (!res.ok) throw new Error('バージョン情報を取得できませんでした');
  const info = await res.json();
  if (typeof info.version !== 'string' || !/^[\w.-]{1,64}$/.test(info.version) || !Array.isArray(info.assets)) {
    throw new Error('バージョン情報が正しくありません');
  }
  return info;
}

/** 指定バージョンの全ファイルを新しいキャッシュに落とす。1つでも失敗したら中止 */
async function download(info) {
  const name = `app-${info.version}`;
  await caches.delete(name);
  const cache = await caches.open(name);
  try {
    const paths = ['./', ...info.assets.filter((p) => typeof p === 'string')];
    await Promise.all(paths.map(async (p) => {
      const u = new URL(p, self.registration.scope);
      if (u.origin !== location.origin) throw new Error('不正なファイル指定です');
      const res = await fetch(u.href, { cache: 'no-store' });
      if (!res.ok) throw new Error(`${p} を取得できませんでした`);
      await cache.put(u.href, res);
    }));
  } catch (err) {
    await caches.delete(name);
    throw err;
  }
  return {
    cache: name,
    version: info.version,
    date: String(info.date || ''),
    message: String(info.message || ''),
    commitUrl: String(info.commitUrl || ''),
  };
}

async function cleanup() {
  const keep = new Set([META]);
  for (const key of ['pinned', 'staged']) {
    const m = await getMeta(key);
    if (m) keep.add(m.cache);
  }
  for (const name of await caches.keys()) {
    if (!keep.has(name)) await caches.delete(name);
  }
}

self.addEventListener('install', (e) => {
  // 初回だけ、その時点のバージョンを固定する。2回目以降(sw.js の更新)では固定を変えない
  e.waitUntil((async () => {
    if (!(await getMeta('pinned'))) await setMeta('pinned', await download(await fetchManifest()));
    await self.skipWaiting();
  })());
});

self.addEventListener('activate', (e) => {
  e.waitUntil(cleanup().then(() => self.clients.claim()));
});

self.addEventListener('fetch', (e) => {
  const u = new URL(e.request.url);
  if (e.request.method !== 'GET' || u.origin !== location.origin) return;
  if (u.pathname.endsWith('/version.json') || u.pathname.endsWith('/sw.js')) return;
  e.respondWith((async () => {
    const pinned = await getMeta('pinned');
    if (pinned) {
      const cache = await caches.open(pinned.cache);
      const hit = (await cache.match(e.request, { ignoreSearch: true }))
        || (e.request.mode === 'navigate' && (await cache.match(url('./'))));
      if (hit) return hit;
    }
    // キャッシュが消された場合などはネットワークから取る
    return fetch(e.request);
  })());
});

self.addEventListener('message', (e) => {
  const port = e.ports[0];
  if (!port) return;
  e.waitUntil((async () => {
    try {
      const { type } = e.data || {};
      if (type === 'status') {
        port.postMessage({ ok: true, pinned: await getMeta('pinned') });
      } else if (type === 'check') {
        const info = await fetchManifest();
        const pinned = await getMeta('pinned');
        if (pinned && pinned.version === info.version) {
          await setMeta('staged', null);
          await cleanup();
          port.postMessage({ ok: true, available: false, pinned });
          return;
        }
        let staged = await getMeta('staged');
        if (!staged || staged.version !== info.version) {
          staged = await download(info);
          await setMeta('staged', staged);
          await cleanup();
        }
        port.postMessage({ ok: true, available: true, pinned, staged });
      } else if (type === 'apply') {
        const staged = await getMeta('staged');
        if (!staged) throw new Error('適用できる更新がありません');
        await setMeta('pinned', staged);
        await setMeta('staged', null);
        await cleanup();
        port.postMessage({ ok: true, pinned: staged });
      } else {
        throw new Error('不明な操作です');
      }
    } catch (err) {
      port.postMessage({ ok: false, error: String(err?.message || err) });
    }
  })());
});
