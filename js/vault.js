// 保管庫のデータ操作(純粋関数)。UIや保存方法には依存しない。
// 削除は「墓標」(deleted: true)として残し、端末間のマージで削除が復活しないようにする。

import { estimateBits, normalizeOptions } from './generator.js';

export const FIELDS = ['title', 'username', 'password', 'url', 'notes'];
// 後から追加した項目。古いデータにはないので、あれば型だけ確かめる
const EXTRA_TYPES = {
  changed: 'boolean', previousPassword: 'string', passwordUpdatedAt: 'number', genOptions: 'object',
};
// これより弱いパスワードは「弱い」と表示する
export const WEAK_BITS = 60;

export function createVault() {
  return { entries: [], updatedAt: Date.now() };
}

export function validateVault(v) {
  if (!v || typeof v !== 'object' || !Array.isArray(v.entries)) {
    throw new Error('保管庫のデータ形式が正しくありません');
  }
  const ids = new Set();
  for (const e of v.entries) {
    if (!e || typeof e.id !== 'string' || !Number.isFinite(e.updatedAt) || ids.has(e.id)
        || (!e.deleted && !FIELDS.every((f) => typeof e[f] === 'string'))
        || Object.entries(EXTRA_TYPES).some(([k, t]) => k in e && typeof e[k] !== t)) {
      throw new Error('保管庫のデータ形式が正しくありません');
    }
    ids.add(e.id);
  }
  if (!Number.isFinite(v.updatedAt)) v.updatedAt = 0;
  return v;
}

function clean(fields) {
  const out = {};
  for (const f of FIELDS) out[f] = typeof fields[f] === 'string' ? fields[f] : '';
  out.changed = fields.changed === true;
  // このサイトで使った生成の型(次に作るときに使う)。渡されなければ今のものを残す
  const gen = normalizeOptions(fields.genOptions);
  if (gen) out.genOptions = gen;
  return out;
}

/**
 * 追加(idなし)または更新(idあり)。新しい保管庫と対象エントリを返す。
 * パスワードが変わったら、元に戻せるよう前のパスワードを残す。
 */
export function upsertEntry(vault, fields, now = Date.now()) {
  const data = clean(fields);
  const existing = fields.id && vault.entries.find((e) => e.id === fields.id);
  let entry;
  let entries;
  if (existing) {
    entry = { ...existing, ...data, updatedAt: Math.max(now, existing.updatedAt + 1) };
    if (data.password !== existing.password) {
      if (existing.password) entry.previousPassword = existing.password;
      entry.passwordUpdatedAt = now;
    }
    entries = vault.entries.map((e) => (e.id === entry.id ? entry : e));
  } else {
    entry = { id: crypto.randomUUID(), ...data, createdAt: now, updatedAt: now, passwordUpdatedAt: now };
    entries = [...vault.entries, entry];
  }
  return { vault: { ...vault, entries, updatedAt: now }, entry };
}

export function clearPreviousPassword(vault, id, now = Date.now()) {
  const entries = vault.entries.map((e) => {
    if (e.id !== id) return e;
    const { previousPassword, ...rest } = e;
    return { ...rest, updatedAt: Math.max(now, e.updatedAt + 1) };
  });
  return { ...vault, entries, updatedAt: now };
}

export function deleteEntry(vault, id, now = Date.now()) {
  const entries = vault.entries.map((e) => (e.id === id
    ? { id, deleted: true, createdAt: e.createdAt, updatedAt: Math.max(now, e.updatedAt + 1) }
    : e));
  return { ...vault, entries, updatedAt: now };
}

export function liveEntries(vault) {
  return vault.entries
    .filter((e) => !e.deleted)
    .sort((a, b) => a.title.localeCompare(b.title, 'ja'));
}

/** 2つの保管庫をマージ。同じidは更新日時が新しい方を採用する */
export function mergeVaults(a, b) {
  const map = new Map();
  for (const e of a.entries) map.set(e.id, e);
  let added = 0;
  let updated = 0;
  for (const e of b.entries) {
    const cur = map.get(e.id);
    if (!cur) {
      map.set(e.id, e);
      if (!e.deleted) added++;
    } else if (e.updatedAt > cur.updatedAt) {
      map.set(e.id, e);
      updated++;
    }
  }
  return {
    vault: { entries: [...map.values()], updatedAt: Math.max(a.updatedAt, b.updatedAt) },
    added,
    updated,
  };
}

/** 項目ごとの注意点(使い回し・弱い)を調べる。id → { reused, weak } */
export function passwordIssues(entries) {
  const count = new Map();
  for (const e of entries) if (e.password) count.set(e.password, (count.get(e.password) || 0) + 1);
  const out = new Map();
  for (const e of entries) {
    out.set(e.id, {
      reused: !!e.password && count.get(e.password) > 1,
      weak: !!e.password && estimateBits(e.password) < WEAK_BITS,
    });
  }
  return out;
}

/** 一覧の絞り込み: all / todo(未変更) / done(変更済み) / risk(要注意) */
export function filterEntries(entries, filter, issues) {
  switch (filter) {
    case 'todo': return entries.filter((e) => !e.changed);
    case 'done': return entries.filter((e) => e.changed);
    case 'risk': return entries.filter((e) => issues.get(e.id)?.reused || issues.get(e.id)?.weak);
    default: return entries;
  }
}

export function searchEntries(entries, query) {
  const q = query.trim().toLowerCase();
  if (!q) return entries;
  return entries.filter((e) => [e.title, e.username, e.url, e.notes]
    .some((s) => s.toLowerCase().includes(q)));
}
