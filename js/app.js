import {
  createKey, seal, openWithKey, openWithPassword, sameKdf, needsUpgrade, WrongPasswordError,
} from './crypto.js';
import {
  createVault, validateVault, upsertEntry, deleteEntry, liveEntries, mergeVaults, searchEntries,
  clearPreviousPassword, passwordIssues, filterEntries,
} from './vault.js';
import {
  generatePassword, estimateBits, PRESETS, normalizeOptions, presetOf,
} from './generator.js';
import { toCsv } from './csv.js';
import { loadEnvelope, saveEnvelope, clearAll, requestPersist } from './store.js';
import { getStatus, checkUpdate, applyUpdate, safeCommitUrl } from './update.js';

// 他のサイトの iframe に埋め込まれていたら動かない(クリックジャッキング対策)
if (window.top !== window.self) {
  document.documentElement.replaceChildren();
  throw new Error('kizupass は埋め込みでは動作しません');
}

const AUTO_LOCK_MS = 5 * 60 * 1000; // 操作がないとロック
const HIDDEN_LOCK_MS = 60 * 1000; // バックグラウンドに回ってからロックするまで
const CLIPBOARD_CLEAR_MS = 30 * 1000;
const MIN_MASTER_LENGTH = 12;
const LAST_EXPORT_KEY = 'kizupass:lastExport';
// ファイル版としてビルドされたときだけ設定される({ standalone, version, date })
const BUILD = globalThis.KIZUPASS_BUILD || null;

const $ = (id) => document.getElementById(id);

// ロック解除中だけメモリに置く。鍵はエクスポート不可の CryptoKey
let session = null; // { keyInfo, vault, lastData: 最後に読み書きした暗号文 }
let editingId = null;
let lockTimer = null;
let hiddenAt = null;
let clipboardTimer = null;
let generatorTarget = null;
let failedUnlocks = 0;
let listFilter = 'all';
let genState = { ...PRESETS.standard }; // 生成画面で選んでいる型
let pendingGenOptions = null; // 編集中の項目で「使う」を押した型(保存時に覚える)

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
  if (!$('busy').hidden) throw new Error('処理中です');
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
  const s = session;
  const stored = await loadEnvelope();
  if (s.lastData && stored?.data !== s.lastData) {
    // 別のタブ・ウィンドウで変更されていたら、上書きせずに取り込んでから保存する
    if (!stored) {
      lock();
      throw new Error('別の画面でデータが削除されました');
    }
    let other;
    try {
      other = validateVault(await openWithKey(stored, s.keyInfo));
    } catch {
      lock();
      throw new Error('別の画面でマスターパスワードが変更されました。もう一度ロック解除してください');
    }
    s.vault = mergeVaults(other, s.vault).vault;
  }
  const env = await seal(s.vault, s.keyInfo);
  await saveEnvelope(env);
  s.lastData = env.data;
}

/** 保存して、失敗したら知らせる。成功なら true */
async function save(okMessage) {
  try {
    await persist();
  } catch (err) {
    toast(err.message || '保存に失敗しました');
    return false;
  }
  if (session) renderList();
  if (okMessage) toast(okMessage);
  return true;
}

function enterMain() {
  show('main');
  $('search').value = '';
  $('update-banner').hidden = true;
  renderList();
  resetLockTimer();
  requestPersist().catch(() => {});
  refreshUpdate({ silent: true });
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
  try {
    await busy(async () => {
      session = { keyInfo: await createKey(pw), vault: createVault(), lastData: null };
      await persist();
    });
  } catch (err) {
    session = null;
    return toast(err.message);
  }
  $('setup-pw').value = '';
  $('setup-pw2').value = '';
  enterMain();
  return toast('保管庫を作成しました');
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
    await busy(async () => {
      const { vault, keyInfo } = await openWithPassword(env, pw);
      session = { keyInfo, vault: validateVault(vault), lastData: null };
      // 旧方式のファイルなら、この端末では新しい方式の鍵で保存する
      if (needsUpgrade(keyInfo)) session.keyInfo = await createKey(pw);
      await persist();
    });
    enterMain();
    toast(`${liveEntries(session.vault).length}件を復元しました`);
  } catch (err) {
    session = null;
    toast(err instanceof WrongPasswordError ? 'パスワードが違います' : err.message);
  }
});

$('unlock-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const pw = $('unlock-pw').value;
  try {
    await busy(async () => {
      const env = await loadEnvelope();
      const { vault, keyInfo } = await openWithPassword(env, pw);
      session = { keyInfo, vault: validateVault(vault), lastData: env.data };
      if (needsUpgrade(keyInfo)) {
        // 旧方式(PBKDF2)から Argon2id へ自動で移行する
        session.keyInfo = await createKey(pw);
        await persist();
      }
    });
    failedUnlocks = 0;
    $('unlock-pw').value = '';
    enterMain();
  } catch (err) {
    session = null;
    $('unlock-pw').select();
    if (!(err instanceof WrongPasswordError)) return toast(err.message);
    // 続けて間違えたら少し待たせる
    failedUnlocks++;
    const wait = failedUnlocks >= 3 ? Math.min(5 * (failedUnlocks - 2), 60) : 0;
    toast(wait ? `パスワードが違います（${wait}秒お待ちください）` : 'パスワードが違います', wait ? wait * 1000 : 2500);
    if (wait) {
      const btn = $('unlock-form').querySelector('button');
      btn.disabled = true;
      setTimeout(() => { btn.disabled = false; }, wait * 1000);
    }
  }
  return undefined;
});

// ---------- 一覧 ----------

function badge(text, cls) {
  return Object.assign(document.createElement('span'), { className: `badge ${cls}`, textContent: text });
}

function renderList() {
  const all = liveEntries(session.vault);
  const issues = passwordIssues(all);
  const items = searchEntries(filterEntries(all, listFilter, issues), $('search').value);
  // 絞り込みの件数と、変更の進み具合
  const counts = {
    all: all.length,
    todo: filterEntries(all, 'todo', issues).length,
    done: filterEntries(all, 'done', issues).length,
    risk: filterEntries(all, 'risk', issues).length,
  };
  for (const chip of document.querySelectorAll('.filters .chip')) {
    chip.querySelector('span').textContent = counts[chip.dataset.filter];
    chip.setAttribute('aria-selected', String(chip.dataset.filter === listFilter));
  }
  $('progress-wrap').hidden = all.length === 0;
  $('progress-bar').style.width = all.length ? `${(counts.done / all.length) * 100}%` : '0';
  $('progress-text').textContent = `${all.length}件中 ${counts.done}件 変更済み`
    + (counts.risk ? `・要注意 ${counts.risk}件（使い回し・弱いパスワード）` : '');
  $('no-match').hidden = all.length === 0 || items.length > 0;
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
    const badges = document.createElement('span');
    badges.className = 'badges';
    badges.append(e.changed ? badge('変更済み', 'done') : badge('未変更', 'todo'));
    if (issues.get(e.id).reused) badges.append(badge('使い回し', 'risk'));
    if (issues.get(e.id).weak) badges.append(badge('弱い', 'risk'));
    main.append(title, sub, badges);
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
for (const chip of document.querySelectorAll('.filters .chip')) {
  chip.addEventListener('click', () => {
    listFilter = chip.dataset.filter;
    renderList();
  });
}
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
  form.elements.changed.checked = !!entry?.changed;
  pendingGenOptions = null;
  $('entry-changed-hint').hidden = true;
  showEntryExtras(entry);
  $('entry-delete').hidden = !entry;
  $('dlg-entry').showModal();
  if (!entry) form.elements.title.focus();
}

function showEntryExtras(entry) {
  // 使い回し・弱いパスワードの注意
  const live = liveEntries(session.vault);
  const issue = entry && passwordIssues(live).get(entry.id);
  const notes = [];
  if (issue?.reused) {
    const others = live.filter((e) => e.id !== entry.id && e.password === entry.password).map((e) => e.title);
    notes.push(`このパスワードは他でも使われています（${others.join('、')}）。サイトごとに別のパスワードにしましょう。`);
  }
  if (issue?.weak) notes.push('このパスワードは弱いです。「パスワードを生成…」で強いものに変えましょう。');
  $('entry-issues').textContent = notes.join('\n');
  $('entry-issues').hidden = notes.length === 0;
  // 前のパスワード(変更に失敗したときに戻せるように)
  const prev = entry?.previousPassword;
  $('prev-row').hidden = !prev;
  $('prev-pw').value = prev || '';
  $('prev-pw').type = 'password';
  $('prev-toggle').textContent = '表示';
  $('prev-date').textContent = prev && entry.passwordUpdatedAt
    ? `（${new Date(entry.passwordUpdatedAt).toLocaleDateString('ja-JP')} に変更）` : '';
}

$('prev-toggle').addEventListener('click', () => {
  const hidden = $('prev-pw').type === 'password';
  $('prev-pw').type = hidden ? 'text' : 'password';
  $('prev-toggle').textContent = hidden ? '隠す' : '表示';
});
$('prev-copy').addEventListener('click', () => copyText($('prev-pw').value, '前のパスワード'));
$('prev-clear').addEventListener('click', async () => {
  if (!editingId || !window.confirm('前のパスワードを消しますか？サイト側で新しいパスワードに変わったことを確認してから消してください。')) return;
  session.vault = clearPreviousPassword(session.vault, editingId);
  if (await save('前のパスワードを消しました')) showEntryExtras(session.vault.entries.find((e) => e.id === editingId));
});

function closeEntry() {
  $('dlg-entry').close();
  form.reset();
  editingId = null;
}

form.addEventListener('submit', async (e) => {
  e.preventDefault();
  const fields = { id: editingId, changed: form.elements.changed.checked };
  if (pendingGenOptions) fields.genOptions = pendingGenOptions;
  for (const name of ['title', 'username', 'password', 'url', 'notes']) fields[name] = form.elements[name].value;
  const before = session.vault;
  session.vault = upsertEntry(session.vault, fields).vault;
  if (!(await save('保存しました'))) {
    if (session) session.vault = before;
    return;
  }
  closeEntry();
});

$('entry-cancel').addEventListener('click', closeEntry);
$('dlg-entry').addEventListener('close', () => { form.reset(); });

$('entry-delete').addEventListener('click', async () => {
  if (!editingId || !window.confirm('このエントリを削除しますか？')) return;
  session.vault = deleteEntry(session.vault, editingId);
  if (await save('削除しました')) closeEntry();
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

$('entry-generate').addEventListener('click', () => {
  const entry = editingId && session.vault.entries.find((e) => e.id === editingId);
  // このサイトで前に使った型から始める
  openGenerator(form.elements.password, pendingGenOptions || entry?.genOptions);
});

// ---------- パスワード生成 ----------

/** 選んでいる型を画面の部品に反映する */
function syncGenControls() {
  $('gen-length').value = genState.length;
  $('gen-length-label').textContent = `${genState.length}文字`;
  $('gen-lower').checked = genState.lower;
  $('gen-upper').checked = genState.upper;
  $('gen-digits').checked = genState.digits;
  $('gen-symbols').value = genState.symbols;
  const preset = presetOf(genState);
  for (const b of document.querySelectorAll('.gen-preset')) b.setAttribute('aria-pressed', String(b.dataset.preset === preset));
}

function regenerate() {
  try {
    const pw = generatePassword(genState);
    $('gen-output').textContent = pw;
    strengthLabel($('gen-strength'), pw);
  } catch (err) {
    $('gen-output').textContent = '';
    $('gen-strength').textContent = err.message;
  }
}

function openGenerator(target, options) {
  generatorTarget = target;
  genState = normalizeOptions(options) || { ...PRESETS.standard };
  $('dlg-generator').querySelector('.gen-detail').open = false;
  syncGenControls();
  regenerate();
  $('dlg-generator').showModal();
}

for (const b of document.querySelectorAll('.gen-preset')) {
  b.addEventListener('click', () => {
    genState = { ...PRESETS[b.dataset.preset] };
    syncGenControls();
    regenerate();
  });
}
for (const id of ['gen-length', 'gen-lower', 'gen-upper', 'gen-digits', 'gen-symbols']) {
  $(id).addEventListener('input', () => {
    genState = {
      length: Number($('gen-length').value),
      lower: $('gen-lower').checked,
      upper: $('gen-upper').checked,
      digits: $('gen-digits').checked,
      symbols: $('gen-symbols').value,
    };
    syncGenControls();
    regenerate();
  });
}
$('gen-refresh').addEventListener('click', regenerate);
$('gen-cancel').addEventListener('click', () => $('dlg-generator').close());
$('gen-use').addEventListener('click', () => {
  const pw = $('gen-output').textContent;
  if (!pw || !generatorTarget) return;
  generatorTarget.value = pw;
  generatorTarget.type = 'text';
  pendingGenOptions = { ...genState };
  $('entry-toggle').textContent = '隠す';
  // 生成したパスワードに変えたら「変更済み」にする(外すこともできる)
  form.elements.changed.checked = true;
  $('entry-changed-hint').hidden = !editingId;
  $('entry-issues').hidden = true; // 注意は前のパスワードについてのものなので消す
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
  showVersion();
  const persisted = await navigator.storage?.persisted?.().catch(() => false);
  $('persist-status').textContent = BUILD
    ? 'ファイル版のデータはこのブラウザの中に保存されます。ブラウザの閲覧データを消すと消えるので、定期的に書き出してください。'
    : persisted
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
    await saveFile(file);
    try { localStorage.setItem(LAST_EXPORT_KEY, String(Date.now())); } catch { /* 使えない環境 */ }
    $('last-export').textContent = lastExportText();
  } catch (err) {
    if (err.name !== 'AbortError') toast('書き出しに失敗しました');
  }
});

const VAULT_FILE_TYPE = { description: 'kizupass 保管庫', accept: { 'application/json': ['.kizupass'] } };

async function saveFile(file, type = VAULT_FILE_TYPE) {
  // スマホ: 共有シート(iPhone は「"ファイル"に保存」で iCloud Drive を選べる)
  if (window.matchMedia('(pointer: coarse)').matches && navigator.canShare?.({ files: [file] })) {
    await navigator.share({ files: [file] });
    return;
  }
  // PC の Chrome / Edge: 保存先(iCloud Drive のフォルダなど)を選べる
  if (window.showSaveFilePicker) {
    const handle = await window.showSaveFilePicker({
      suggestedName: file.name,
      types: [type],
    });
    const w = await handle.createWritable();
    await w.write(file);
    await w.close();
    return;
  }
  const a = document.createElement('a');
  a.href = URL.createObjectURL(file);
  a.download = file.name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 10_000);
}

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
    if (err.message === '処理中です') return;
    toast(err instanceof WrongPasswordError ? 'パスワードが違います' : err.message);
  }
});

// ---------- 使い方 ----------

for (const btn of document.querySelectorAll('.help-open')) {
  btn.addEventListener('click', () => $('dlg-help').showModal());
}

// ---------- 他のパスワード管理へ移す(暗号化されない CSV) ----------

const CSV_TARGETS = {
  apple: {
    label: 'Apple の「パスワード」',
    steps: [
      'Mac：「パスワード」アプリを開き、メニューの「ファイル」→「パスワードを読み込む」で、書き出した CSV を選ぶ。',
      'iPhone（iOS 18.2 以降）：「設定」→「アプリ」→「Safari」→「読み込む」で、書き出した CSV を選ぶ。',
      '読み込めたら、CSV ファイルを削除する（ゴミ箱・「最近削除した項目」からも）。',
    ],
  },
  chrome: {
    label: 'Google Chrome',
    steps: [
      'パソコンの Chrome で、アドレスバーに chrome://password-manager/settings と入力して開く。',
      '「パスワードをインポート」→「ファイルを選択」で、書き出した CSV を選ぶ。',
      '読み込めたら、CSV ファイルを削除する（ゴミ箱からも）。',
    ],
  },
};

function showInfo({ title, steps, warn = '', skipped = [] }) {
  $('info-title').textContent = title;
  $('info-steps').replaceChildren(...steps.map((t) => Object.assign(document.createElement('li'), { textContent: t })));
  $('info-warn').textContent = warn;
  $('info-warn').hidden = !warn;
  $('info-skipped-list').replaceChildren(...skipped.map((t) => Object.assign(document.createElement('li'), { textContent: t })));
  $('info-skipped').hidden = skipped.length === 0;
  $('dlg-info').showModal();
}

async function exportCsv(format) {
  const target = CSV_TARGETS[format];
  const ok = window.confirm(
    `${target.label}に読み込むためのファイルを書き出します。\n\n`
    + 'このファイルは暗号化されず、誰でも中身を読めます。\n'
    + '・iCloud Drive やメールなど、他人や他のサービスに渡る場所には保存しない\n'
    + '・Excel などで開かない\n'
    + '・読み込んだらすぐ削除する\n\n続けますか？',
  );
  if (!ok) return;
  const pw = await askPassword({ title: '確認のためマスターパスワードを入力', message: '暗号化されていないファイルを書き出すため、本人確認をします。' });
  if (pw === null) return;
  try {
    await busy(async () => openWithPassword(await loadEnvelope(), pw));
  } catch (err) {
    toast(err instanceof WrongPasswordError ? 'パスワードが違います' : err.message);
    return;
  }
  const { csv, count, skipped } = toCsv(liveEntries(session.vault), format);
  if (count === 0) {
    showInfo({ title: '書き出せる項目がありません', steps: ['書き出すには、各項目に URL を登録してください。'], skipped });
    return;
  }
  const d = new Date();
  const stamp = `${d.getFullYear()}${String(d.getMonth() + 1).padStart(2, '0')}${String(d.getDate()).padStart(2, '0')}`;
  const file = new File([csv], `kizupass-${format}-${stamp}.csv`, { type: 'text/csv' });
  try {
    await saveFile(file, { description: 'CSV', accept: { 'text/csv': ['.csv'] } });
  } catch (err) {
    if (err.name !== 'AbortError') toast('書き出しに失敗しました');
    return;
  }
  $('dlg-settings').close();
  showInfo({
    title: `${count}件を書き出しました`,
    steps: target.steps,
    warn: 'CSV ファイルは暗号化されていません。読み込みが終わったら必ず削除してください。',
    skipped,
  });
}

$('btn-csv-apple').addEventListener('click', () => exportCsv('apple'));
$('btn-csv-chrome').addEventListener('click', () => exportCsv('chrome'));

/** 現在の鍵と同じ設定(ソルト含む)で暗号化されていれば、パスワード再入力なしで開く */
async function openWithSameKey(env) {
  return sameKdf(env?.kdf, session.keyInfo.kdf) ? openWithKey(env, session.keyInfo) : null;
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
  const before = session.keyInfo;
  try {
    await busy(async () => {
      session.keyInfo = await createKey(next);
      await persist();
    });
  } catch (err) {
    if (session) session.keyInfo = before;
    return toast(err.message);
  }
  return toast('マスターパスワードを変更しました');
});

$('btn-wipe').addEventListener('click', async () => {
  if (!window.confirm('この端末の保管庫を削除します。書き出したファイルがなければ元に戻せません。続けますか？')) return;
  if (window.prompt('確認のため「削除」と入力してください') !== '削除') return;
  await clearAll();
  session = null;
  clearTimeout(lockTimer);
  for (const d of document.querySelectorAll('dialog[open]')) d.close();
  show('setup');
  toast('削除しました');
});

// ---------- アプリの更新(利用者が承認したときだけ) ----------

async function showVersion() {
  if (BUILD) {
    $('app-version').textContent = `ファイル版 ${BUILD.version}${BUILD.date ? `（${BUILD.date}）` : ''}。サーバーに接続しないため自動では更新されません。`;
    return;
  }
  $('app-version').textContent = '確認中…';
  try {
    const st = await getStatus();
    const p = st?.pinned;
    $('app-version').textContent = p
      ? `使用中: ${p.version}${p.date ? `（${p.date}）` : ''}`
      : 'オフライン用のデータがまだ準備されていません。一度アプリを開き直してください。';
  } catch {
    $('app-version').textContent = '確認できませんでした';
  }
}

function showUpdateBanner(staged) {
  $('update-info').textContent = `${staged.version}${staged.date ? `（${staged.date}）` : ''}: ${staged.message}`;
  const link = safeCommitUrl(staged.commitUrl);
  $('update-link').hidden = !link;
  if (link) $('update-link').href = link;
  $('update-banner').hidden = false;
}

async function refreshUpdate({ silent }) {
  if (BUILD) return;
  try {
    const r = await checkUpdate();
    if (!r) {
      if (!silent) toast('いまは更新を確認できません。アプリを開き直してください');
    } else if (r.available) {
      showUpdateBanner(r.staged);
      if (!silent) {
        $('dlg-settings').close();
        toast('新しいバージョンがあります');
      }
    } else if (!silent) {
      toast('最新のバージョンです');
    }
  } catch (err) {
    if (!silent) toast(err.message);
  }
}

$('btn-check-update').addEventListener('click', () => refreshUpdate({ silent: false }));
$('btn-offline').addEventListener('click', () => {
  const a = document.createElement('a');
  a.href = 'kizupass-offline.html';
  a.download = 'kizupass-offline.html';
  a.click();
});
// ファイル版では更新確認とダウンロードは不要
$('btn-check-update').hidden = !!BUILD;
$('btn-offline').hidden = !!BUILD;
$('offline-note').hidden = !!BUILD;
$('update-later').addEventListener('click', () => { $('update-banner').hidden = true; });
$('update-apply').addEventListener('click', async () => {
  if (!window.confirm('新しいバージョンに更新して再読み込みします。よろしいですか？')) return;
  try {
    await applyUpdate();
    window.location.reload();
  } catch (err) {
    toast(err.message);
  }
});

// ---------- 起動 ----------

if (!BUILD && 'serviceWorker' in navigator) {
  navigator.serviceWorker.register('sw.js').catch(() => {});
}

loadEnvelope()
  .then((env) => show(env ? 'unlock' : 'setup'))
  .catch(() => {
    show('setup');
    toast('この環境では保存領域が使えません');
  });
