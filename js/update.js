// Service Worker とのやりとり(バージョン確認・更新の適用)

function ask(type, timeout = 60_000) {
  const ctl = navigator.serviceWorker?.controller;
  if (!ctl) return Promise.resolve(null);
  return new Promise((resolve, reject) => {
    const ch = new MessageChannel();
    const timer = setTimeout(() => reject(new Error('応答がありません')), timeout);
    ch.port1.onmessage = (e) => {
      clearTimeout(timer);
      if (e.data?.ok) resolve(e.data);
      else reject(new Error(e.data?.error || '失敗しました'));
    };
    ctl.postMessage({ type }, [ch.port2]);
  });
}

export const getStatus = () => ask('status', 10_000);
export const checkUpdate = () => ask('check');
export const applyUpdate = () => ask('apply');

/** GitHub のコミットページへのリンクだけを許可する */
export function safeCommitUrl(u) {
  try {
    const parsed = new URL(u);
    return parsed.protocol === 'https:' && parsed.hostname === 'github.com' ? parsed.href : null;
  } catch {
    return null;
  }
}
