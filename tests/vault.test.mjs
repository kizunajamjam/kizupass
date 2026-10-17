import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  createVault, upsertEntry, deleteEntry, liveEntries, mergeVaults, searchEntries, validateVault,
} from '../js/vault.js';
import { generatePassword, estimateBits, CHARSETS } from '../js/generator.js';

test('追加・更新・削除', () => {
  let v = createVault();
  const r = upsertEntry(v, { title: 'A', password: 'x' }, 1000);
  v = r.vault;
  v = upsertEntry(v, { id: r.entry.id, title: 'A2', password: 'y' }, 2000).vault;
  assert.equal(liveEntries(v)[0].title, 'A2');
  v = deleteEntry(v, r.entry.id, 3000);
  assert.equal(liveEntries(v).length, 0);
  const tomb = v.entries[0];
  assert.equal(tomb.deleted, true);
  assert.equal(tomb.password, undefined, '削除時に中身を残さない');
});

test('同時刻の更新でも updatedAt は必ず増える', () => {
  const r = upsertEntry(createVault(), { title: 'A' }, 1000);
  const v2 = upsertEntry(r.vault, { id: r.entry.id, title: 'B' }, 1000).vault;
  assert.ok(v2.entries[0].updatedAt > 1000);
});

test('マージは新しい方を採用し、削除も伝わる', () => {
  const base = upsertEntry(createVault(), { title: 'shared', password: 'old' }, 1000);
  const id = base.entry.id;
  // 端末A: 更新 / 端末B: 新規追加
  const a = upsertEntry(base.vault, { id, title: 'shared', password: 'new' }, 2000).vault;
  const b = upsertEntry(base.vault, { title: 'onlyB' }, 1500).vault;

  const m1 = mergeVaults(a, b);
  assert.equal(m1.added, 1);
  assert.equal(m1.updated, 0);
  assert.equal(liveEntries(m1.vault).find((e) => e.id === id).password, 'new');
  assert.equal(liveEntries(m1.vault).length, 2);

  // 逆向きでも同じ結果
  const m2 = mergeVaults(b, a);
  assert.equal(m2.updated, 1);
  assert.deepEqual(
    liveEntries(m1.vault).map((e) => e.password),
    liveEntries(m2.vault).map((e) => e.password),
  );

  // 端末Bで削除 → Aにマージすると消える。古い方から再マージしても復活しない
  const bDeleted = deleteEntry(m2.vault, id, 3000);
  const m3 = mergeVaults(m1.vault, bDeleted);
  assert.ok(!liveEntries(m3.vault).some((e) => e.id === id));
  const m4 = mergeVaults(m3.vault, a);
  assert.ok(!liveEntries(m4.vault).some((e) => e.id === id));
});

test('検索', () => {
  let v = createVault();
  v = upsertEntry(v, { title: 'GitHub', username: 'kizu' }).vault;
  v = upsertEntry(v, { title: 'Amazon', url: 'amazon.co.jp' }).vault;
  assert.equal(searchEntries(liveEntries(v), 'git').length, 1);
  assert.equal(searchEntries(liveEntries(v), 'CO.JP').length, 1);
  assert.equal(searchEntries(liveEntries(v), '').length, 2);
});

test('不正なデータは拒否', () => {
  assert.throws(() => validateVault({}));
  assert.throws(() => validateVault({ entries: [{ title: 'no id' }] }));
});

test('生成したパスワードは長さと文字種の条件を満たす', () => {
  for (let i = 0; i < 200; i++) {
    const pw = generatePassword({ length: 12 });
    assert.equal(pw.length, 12);
    for (const set of Object.values(CHARSETS)) assert.ok([...pw].some((c) => set.includes(c)));
  }
  const digits = generatePassword({ length: 30, lower: false, upper: false, symbols: false });
  assert.match(digits, /^[0-9]{30}$/);
  assert.throws(() => generatePassword({ lower: false, upper: false, digits: false, symbols: false }));
  assert.ok(estimateBits(generatePassword({ length: 20 })) > 120);
});
