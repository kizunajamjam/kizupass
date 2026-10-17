// 保管庫のデータ操作(純粋関数)。UIや保存方法には依存しない。
// 削除は「墓標」(deleted: true)として残し、端末間のマージで削除が復活しないようにする。

export const FIELDS = ['title', 'username', 'password', 'url', 'notes'];

export function createVault() {
  return { entries: [], updatedAt: Date.now() };
}

export function validateVault(v) {
  if (!v || typeof v !== 'object' || !Array.isArray(v.entries)) {
    throw new Error('保管庫のデータ形式が正しくありません');
  }
  for (const e of v.entries) {
    if (!e || typeof e.id !== 'string' || typeof e.updatedAt !== 'number') {
      throw new Error('保管庫のデータ形式が正しくありません');
    }
  }
  return v;
}

function clean(fields) {
  const out = {};
  for (const f of FIELDS) out[f] = typeof fields[f] === 'string' ? fields[f] : '';
  return out;
}

/** 追加(idなし)または更新(idあり)。新しい保管庫と対象エントリを返す */
export function upsertEntry(vault, fields, now = Date.now()) {
  const data = clean(fields);
  const existing = fields.id && vault.entries.find((e) => e.id === fields.id);
  let entry;
  let entries;
  if (existing) {
    entry = { ...existing, ...data, updatedAt: Math.max(now, existing.updatedAt + 1) };
    entries = vault.entries.map((e) => (e.id === entry.id ? entry : e));
  } else {
    entry = { id: crypto.randomUUID(), ...data, createdAt: now, updatedAt: now };
    entries = [...vault.entries, entry];
  }
  return { vault: { ...vault, entries, updatedAt: now }, entry };
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

export function searchEntries(entries, query) {
  const q = query.trim().toLowerCase();
  if (!q) return entries;
  return entries.filter((e) => [e.title, e.username, e.url, e.notes]
    .some((s) => s.toLowerCase().includes(q)));
}
