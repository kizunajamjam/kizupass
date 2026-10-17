import {
  createKey, seal, openWithKey, openWithPassword, toB64, WrongPasswordError,
} from './crypto.js';
import {
  createVault, validateVault, upsertEntry, deleteEntry, liveEntries, mergeVaults, searchEntries,
} from './vault.js';
import { generatePassword, estimateBits } from './generator.js';
import { loadEnvelope, saveEnvelope, clearAll, requestPersist } from './store.js';

const AUTO_LOCK_MS = 5 * 60 * 1000; // 操作がないとロック
const HIDDEN_LOCK_MS = 60 * 1000; // バックグラウンドに回ってからロックするまで
const CLIPBOARD_CLEAR_MS = 30 * 1000;
const MIN_MASTER_LENGTH = 12;
const LAST_EXPORT_KEY = 'kizupass:lastExport';

const $ = (id) => document.getElementById(id);

// ロック解除中だけメモリに置く。鍵はエクスポート不可の CryptoKey
let session = null; // { keyInfo, vault }
let editingId = null;
let lockTimer = null;
let hiddenAt = null;
let clipboardTimer = null;
let generatorTarget = null;

// ---------- 画面 ----------

function show(view) {
  for (const v of document.querySelectorAll('.view')) v.hidden = v.id !== `view-${view}`;
}

function toast(msg, ms = 2500) {
  const t = $('toast');
  t.textContent = msg;
  t.hidden = false;
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => { t.hidden = true; }, ms);
}

async function busy(fn) {
  $('busy').hidden = false;
  // 表示を反映させてから重い処理(鍵導出)を始める
  await new Promise((r) => requestAnimationFrame(() => setTimeout(r, 0)));
  try {
    return await fn();
  } finally {
    $('busy').hidden = true;
  }
}

function strengthLabel(el, pw) {
  if (!pw) { el.textContent = ''; el.className = 'strength'; return; }
  const bits = estimateBits(pw);
  const [label, cls] = bits >= 100 ? ['とても強い', 's4'] : bits >= 75 ? ['強い', 's3']
    : bits >= 55 ? ['普通', 's2'] : ['弱い', 's1'];
  el.textContent = `強度: ${label}（約${bits}ビット）`;
  el.className = `strength ${cls}`;
}

/** パスワード入力ダイアログ。キャンセルなら null */
function askPassword({ title, message = '', confirm = false }) {
  const dlg = $('dlg-prompt');
  const pw = $('prompt-pw');
  const pw2 = $('prompt-pw2');
  $('prompt-title').textContent = title;
  $('prompt-message').textContent = message;
  pw.value = '';
  pw2.value = '';
  pw2.hidden = !confirm;
  return new Promise((resolve) => {
    const done = (value) => {
      $('prompt-form').onsubmit = null;
      $('prompt-cancel').onclick = null;
      dlg.onclose = null;
      dlg.close();
      pw.value = '';
      pw2.value = '';
      resolve(value);
    };
    $('prompt-form').onsubmit = (e) => {
      e.preventDefault();
      if (confirm) {
        if (pw.value.length < MIN_MASTER_LENGTH) return toast(`${MIN_MASTER_LENGTH}文字以上にしてください`);
        if (pw.value !== pw2.value) return toast('2回の入力が一致しません');
      }
      if (!pw.value) return undefined;
      return done(pw.value);
    };
    $('prompt-cancel').onclick = () => done(null);
    // 直前のダイアログの close イベントが遅れて届いても無視する
    dlg.onclose = () => { if (!dlg.open) done(null); };
    dlg.showModal();
    pw.focus();
  });
}

function pickFile() {
  const input = $('file-input');
  input.value = '';
  return new Promise((resolve) => {
    input.onchange = () => resolve(input.files[0] || null);
    input.click();
  });
}

async function readEnvelopeFile(file) {
  try {
    return JSON.parse(await file.text());
  } catch {
    throw new Error('ファイルを読み込めませんでした');
  }
}

// ---------- セッション ----------

async function persist() {
  await saveEnvelope(await seal(session.vault, session.keyInfo));
}

function startSession(keyInfo, vault) {
  session = { keyInfo, vault: validateVault(vault) };
  show('main');
  $('search').value = '';
  renderList();
  resetLockTimer();
  requestPersist().catch(() => {});
}

function lock() {
  session = null;
  editingId = null;
  clearTimeout(lockTimer);
  for (const d of document.querySelectorAll('dialog[open]')) d.close();
  $('entry-list').replaceChildren();
  $('search').value = '';
  $('unlock-pw').value = '';
  show('unlock');
}

function resetLockTimer() {
  if (!session) return;
  clearTimeout(lockTimer);
  lockTimer = setTimeout(lock, AUTO_LOCK_MS);
}

for (const ev of ['pointerdown', 'keydown', 'input', 'scroll']) {
  document.addEventListener(ev, resetLockTimer, { passive: true, capture: true });
}

document.addEventListener('visibilitychange', () => {
  if (document.hidden) {
    hiddenAt = Date.now();
  } else if (session && hiddenAt && Date.now() - hiddenAt > HIDDEN_LOCK_MS) {
    lock();
  }
});

// ---------- 初回設定・ロック解除 ----------

$('setup-pw').addEventListener('input', (e) => strengthLabel($('setup-strength'), e.target.value));

$('setup-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const pw = $('setup-pw').value;
  if (pw.length < MIN_MASTER_LENGTH) return toast(`${MIN_MASTER_LENGTH}文字以上にしてください`);
  if (pw !== $('setup-pw2').value) return toast('2回の入力が一致しません');
  await busy(async () => {
    const keyInfo = await createKey(pw);
    session = { keyInfo, vault: createVault() };
    await persist();
  });
  $('setup-pw').value = '';
  $('setup-pw2').value = '';
  startSession(session.keyInfo, session.vault);
  toast('保管庫を作成しました');
});

$('setup-restore').addEventListener('click', async () => {
  const file = await pickFile();
  if (!file) return;
  try {
    const env = await readEnvelopeFile(file);
    const pw = await askPassword({
      title: 'バックアップの復元',
      message: 'このファイルを書き出したときのマスターパスワードを入力してください。この端末でも同じパスワードを使います。',
    });
    if (pw === null) return;
    const { vault, keyInfo } = await busy(() => openWithPassword(env, pw));
    session = { keyInfo, vault: validateVault(vault) };
    await persist();
    startSession(keyInfo, session.vault);
    toast(`${liveEntries(session.vault).length}件を復元しました`);
  } catch (err) {
    toast(err.message);
  }
});

$('unlock-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const pw = $('unlock-pw').value;
  try {
    const env = await loadEnvelope();
    const { vault, keyInfo } = await busy(() => openWithPassword(env, pw));
    $('unlock-pw').value = '';
    startSession(keyInfo, vault);
  } catch (err) {
    $('unlock-pw').select();
    toast(err instanceof WrongPasswordError ? 'パスワードが違います' : err.message);
  }
});

// ---------- 一覧 ----------

function renderList() {
  const all = liveEntries(session.vault);
  const items = searchEntries(all, $('search').value);
  const list = $('entry-list');
  list.replaceChildren(...items.map((e) => {
    const li = document.createElement('li');
    const main = document.createElement('button');
    main.type = 'button';
    main.className = 'entry';
    const title = document.createElement('span');
    title.className = 'title';
    title.textContent = e.title || '(無題)';
    const sub = document.createElement('span');
    sub.className = 'sub';
    sub.textContent = e.username || e.url;
    main.append(title, sub);
    main.addEventListener('click', () => openEntry(e.id));
    const copy = document.createElement('button');
    copy.type = 'button';
    copy.className = 'copy';
    copy.textContent = 'コピー';
    copy.setAttribute('aria-label', `${e.title} のパスワードをコピー`);
    copy.disabled = !e.password;
    copy.addEventListener('click', () => copyText(e.password, 'パスワード'));
    li.append(main, copy);
    return li;
  }));
  $('empty').hidden = all.length > 0;
}

$('search').addEventListener('input', renderList);
$('btn-lock').addEventListener('click', lock);
$('btn-add').addEventListener('click', () => openEntry(null));

async function copyText(text, label) {
  if (!text) return;
  try {
    await navigator.clipboard.writeText(text);
    toast(`${label}をコピーしました（${CLIPBOARD_CLEAR_MS / 1000}秒後に消去）`);
    clearTimeout(clipboardTimer);
    clipboardTimer = setTimeout(() => {
      // 他の内容に置き換わっていたら消さない(読めない環境では無条件に消す)
      navigator.clipboard.readText()
        .then((cur) => (cur === text ? navigator.clipboard.writeText('') : undefined))
        .catch(() => navigator.clipboard.writeText('').catch(() => {}));
    }, CLIPBOARD_CLEAR_MS);
  } catch {
    toast('コピーできませんでした');
  }
}

// ---------- 登録・編集 ----------

const form = $('entry-form');

function openEntry(id) {
  editingId = id;
  const entry = id ? session.vault.entries.find((e) => e.id === id) : null;
  $('entry-heading').textContent = entry ? '編集' : '追加';
  for (const name of ['title', 'username', 'password', 'url', 'notes']) {
    form.elements[name].value = entry ? entry[name] : '';
  }
  form.elements.password.type = 'password';
  $('entry-toggle').textContent = '表示';
  $('entry-delete').hidden = !entry;
  $('dlg-entry').showModal();
  if (!entry) form.elements.title.focus();
}

function closeEntry() {
  $('dlg-entry').close();
  form.reset();
  editingId = null;
}

form.addEventListener('submit', async (e) => {
  e.preventDefault();
  const fields = { id: editingId };
  for (const name of ['title', 'username', 'password', 'url', 'notes']) fields[name] = form.elements[name].value;
  const before = session.vault;
  session.vault = upsertEntry(session.vault, fields).vault;
  try {
    await persist();
  } catch {
    session.vault = before;
    return toast('保存に失敗しました');
  }
  closeEntry();
  renderList();
  return toast('保存しました');
});

$('entry-cancel').addEventListener('click', closeEntry);
$('dlg-entry').addEventListener('close', () => { form.reset(); });

$('entry-delete').addEventListener('click', async () => {
  if (!editingId || !window.confirm('このエントリを削除しますか？')) return;
  session.vault = deleteEntry(session.vault, editingId);
  await persist();
  closeEntry();
  renderList();
  toast('削除しました');
});

$('entry-toggle').addEventListener('click', () => {
  const input = form.elements.password;
  const hidden = input.type === 'password';
  input.type = hidden ? 'text' : 'password';
  $('entry-toggle').textContent = hidden ? '隠す' : '表示';
});

for (const btn of form.querySelectorAll('[data-copy]')) {
  const name = btn.dataset.copy;
  btn.addEventListener('click', () => copyText(form.elements[name].value, name === 'password' ? 'パスワード' : 'ユーザー名'));
}

$('entry-open').addEventListener('click', () => {
  let url = form.elements.url.value.trim();
  if (!url) return;
  if (!/^https?:\/\//i.test(url)) url = `https://${url}`;
  // http(s) 以外のスキーム(javascript: など)は開かない
  try {
    const u = new URL(url);
    if (u.protocol === 'https:' || u.protocol === 'http:') window.open(u.href, '_blank', 'noopener,noreferrer');
  } catch {
    toast('URLが正しくありません');
  }
});

$('entry-generate').addEventListener('click', () => openGenerator(form.elements.password));

// ---------- パスワード生成 ----------

function genOptions() {
  return {
    length: Number($('gen-length').value),
    lower: $('gen-lower').checked,
    upper: $('gen-upper').checked,
    digits: $('gen-digits').checked,
    symbols: $('gen-symbols').checked,
  };
}

function regenerate() {
  $('gen-length-label').textContent = $('gen-length').value;
  try {
    const pw = generatePassword(genOptions());
    $('gen-output').textContent = pw;
    strengthLabel($('gen-strength'), pw);
  } catch (err) {
    $('gen-output').textContent = '';
    $('gen-strength').textContent = err.message;
  }
}

function openGenerator(target) {
  generatorTarget = target;
  regenerate();
  $('dlg-generator').showModal();
}

for (const id of ['gen-length', 'gen-lower', 'gen-upper', 'gen-digits', 'gen-symbols']) {
  $(id).addEventListener('input', regenerate);
}
$('gen-refresh').addEventListener('click', regenerate);
$('gen-cancel').addEventListener('click', () => $('dlg-generator').close());
$('gen-use').addEventListener('click', () => {
  const pw = $('gen-output').textContent;
  if (!pw || !generatorTarget) return;
  generatorTarget.value = pw;
  generatorTarget.type = 'text';
  $('entry-toggle').textContent = '隠す';
  $('dlg-generator').close();
});
$('dlg-generator').addEventListener('close', () => { $('gen-output').textContent = ''; });

// ---------- 設定・同期 ----------

function lastExportText() {
  let t = null;
  try { t = localStorage.getItem(LAST_EXPORT_KEY); } catch { /* 使えない環境 */ }
  return t ? `最後に書き出した日時: ${new Date(Number(t)).toLocaleString('ja-JP')}` : 'まだ書き出していません。バックアップのため一度書き出してください。';
}

$('btn-settings').addEventListener('click', async () => {
  $('last-export').textContent = lastExportText();
  const persisted = await navigator.storage?.persisted?.().catch(() => false);
  $('persist-status').textContent = persisted
    ? 'この端末の保存領域は自動削除されない設定です。'
    : 'ブラウザが容量不足時などにデータを消す可能性があります。ホーム画面に追加して使い、定期的に書き出してください。';
  $('dlg-settings').showModal();
});
$('settings-close').addEventListener('click', () => $('dlg-settings').close());

$('btn-export').addEventListener('click', async () => {
  const env = await seal(session.vault, session.keyInfo);
  const d = new Date();
  const stamp = `${d.getFullYear()}${String(d.getMonth() + 1).padStart(2, '0')}${String(d.getDate()).padStart(2, '0')}`;
  const name = `kizupass-${stamp}.kizupass`;
  const file = new File([JSON.stringify(env)], name, { type: 'application/json' });
  try {
    // iPhone では共有シートから「"ファイル"に保存」→ iCloud Drive を選べる
    if (navigator.canShare?.({ files: [file] })) {
      await navigator.share({ files: [file] });
    } else {
      const a = document.createElement('a');
      a.href = URL.createObjectURL(file);
      a.download = name;
      a.click();
      setTimeout(() => URL.revokeObjectURL(a.href), 10_000);
    }
    try { localStorage.setItem(LAST_EXPORT_KEY, String(Date.now())); } catch { /* 使えない環境 */ }
    $('last-export').textContent = lastExportText();
  } catch (err) {
    if (err.name !== 'AbortError') toast('書き出しに失敗しました');
  }
});

$('btn-import').addEventListener('click', async () => {
  const file = await pickFile();
  if (!file) return;
  try {
    const env = await readEnvelopeFile(file);
    let incoming = null;
    try {
      // 同じ鍵で暗号化されたファイルならパスワード入力は不要
      incoming = await openWithSameKey(env);
    } catch (err) {
      if (!(err instanceof WrongPasswordError)) throw err;
    }
    if (!incoming) {
      const pw = await askPassword({
        title: 'ファイルのパスワード',
        message: 'このファイルは別のマスターパスワードで暗号化されています。そのパスワードを入力してください。',
      });
      if (pw === null) return;
      incoming = (await busy(() => openWithPassword(env, pw))).vault;
    }
    const result = mergeVaults(session.vault, validateVault(incoming));
    session.vault = result.vault;
    await persist();
    renderList();
    toast(`マージしました（追加 ${result.added}件・更新 ${result.updated}件）`, 4000);
  } catch (err) {
    toast(err instanceof WrongPasswordError ? 'パスワードが違います' : err.message);
  }
});

/** 現在の鍵とソルトが同じなら、パスワード再入力なしで開く */
async function openWithSameKey(env) {
  const { salt, iterations } = session.keyInfo;
  const same = env.kdf?.salt && env.kdf.iterations === iterations
    && env.kdf.salt === toB64(salt);
  return same ? openWithKey(env, session.keyInfo) : null;
}

$('btn-change-pw').addEventListener('click', async () => {
  const current = await askPassword({ title: '現在のマスターパスワード' });
  if (current === null) return;
  try {
    await busy(async () => openWithPassword(await loadEnvelope(), current));
  } catch {
    return toast('パスワードが違います');
  }
  const next = await askPassword({
    title: '新しいマスターパスワード',
    message: `${MIN_MASTER_LENGTH}文字以上。古いパスワードで書き出したファイルも、読み込み時に古いパスワードを入力すればマージできます。`,
    confirm: true,
  });
  if (next === null) return undefined;
  await busy(async () => {
    session.keyInfo = await createKey(next);
    await persist();
  });
  return toast('マスターパスワードを変更しました');
});

$('btn-wipe').addEventListener('click', async () => {
  if (!window.confirm('この端末の保管庫を削除します。書き出したファイルがなければ元に戻せません。続けますか？')) return;
  if (window.prompt('確認のため「削除」と入力してください') !== '削除') return;
  await clearAll();
  session = null;
  for (const d of document.querySelectorAll('dialog[open]')) d.close();
  show('setup');
  toast('削除しました');
});

// ---------- 起動 ----------

if ('serviceWorker' in navigator) {
  navigator.serviceWorker.register('sw.js').catch(() => {});
}

loadEnvelope()
  .then((env) => show(env ? 'unlock' : 'setup'))
  .catch(() => {
    show('setup');
    toast('この環境では保存領域が使えません');
  });
