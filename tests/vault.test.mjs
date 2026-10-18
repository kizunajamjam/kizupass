import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  createVault, upsertEntry, deleteEntry, liveEntries, mergeVaults, searchEntries, validateVault,
  clearPreviousPassword, passwordIssues, filterEntries,
} from '../js/vault.js';
import {
  generatePassword, estimateBits, CHARSETS, PRESETS, SAFE_SYMBOLS, presetOf, normalizeOptions,
} from '../js/generator.js';

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
  const ok = { id: 'a', updatedAt: 1, title: 't', username: '', password: '', url: '', notes: '' };
  assert.doesNotThrow(() => validateVault({ entries: [ok], updatedAt: 1 }));
  assert.throws(() => validateVault({ entries: [{ ...ok, title: 123 }] }), undefined, '文字列以外の項目');
  assert.throws(() => validateVault({ entries: [ok, { ...ok }] }), undefined, 'id の重複');
  assert.throws(() => validateVault({ entries: [{ ...ok, updatedAt: Infinity }] }));
  assert.doesNotThrow(() => validateVault({ entries: [{ id: 'b', updatedAt: 2, deleted: true }] }), '墓標は中身なしでよい');
});

test('生成したパスワードは長さと文字種の条件を満たす', () => {
  // おすすめ: 16文字・英数字、記号なし
  for (let i = 0; i < 200; i++) {
    const pw = generatePassword();
    assert.match(pw, /^[A-Za-z0-9]{16}$/);
    for (const set of [CHARSETS.lower, CHARSETS.upper, CHARSETS.digits]) assert.ok([...pw].some((c) => set.includes(c)));
  }
  assert.ok(estimateBits(generatePassword()) >= 95);
  // 記号あり: 多くのサイトで使える記号だけ
  for (let i = 0; i < 200; i++) {
    const pw = generatePassword(PRESETS.symbol);
    assert.equal(pw.length, 16);
    assert.ok([...pw].some((c) => SAFE_SYMBOLS.includes(c)));
    assert.match(pw, /^[A-Za-z0-9\-_.!@#]+$/);
  }
  assert.match(generatePassword(PRESETS.short), /^[A-Za-z0-9]{12}$/);
  assert.match(generatePassword(PRESETS.pin), /^[0-9]{6}$/);
  const all = generatePassword({ length: 30, symbols: 'all' });
  assert.ok([...all].some((c) => CHARSETS.symbols.includes(c)));
  assert.throws(() => generatePassword({ lower: false, upper: false, digits: false, symbols: 'none' }));
});

test('生成の型の判定と、保存データの整形', () => {
  assert.equal(presetOf(PRESETS.symbol), 'symbol');
  assert.equal(presetOf({ ...PRESETS.standard, length: 20 }), null);
  assert.deepEqual(normalizeOptions({ length: 999, lower: true, symbols: 'evil' }),
    { length: 64, lower: true, upper: false, digits: false, symbols: 'none' });
  assert.equal(normalizeOptions({ lower: false }), null);
  assert.equal(normalizeOptions('x'), null);
});

test('サイトごとに使った生成の型を覚える', () => {
  const r = upsertEntry(createVault(), { title: 'Bank', password: 'p', genOptions: PRESETS.symbol }, 1);
  assert.deepEqual(r.entry.genOptions, PRESETS.symbol);
  // 渡さなければ前の型を残す
  const v = upsertEntry(r.vault, { id: r.entry.id, title: 'Bank2', password: 'p' }, 2).vault;
  assert.deepEqual(v.entries[0].genOptions, PRESETS.symbol);
  assert.throws(() => validateVault({ entries: [{ ...v.entries[0], genOptions: 'x' }] }));
});

test('パスワードを変えると前のパスワードが残り、変更済みの印は保存される', () => {
  const r = upsertEntry(createVault(), { title: 'A', password: 'old-pass' }, 1000);
  assert.equal(r.entry.changed, false);
  assert.equal(r.entry.passwordUpdatedAt, 1000);
  let v = upsertEntry(r.vault, { id: r.entry.id, title: 'A', password: 'new-pass', changed: true }, 2000).vault;
  let e = v.entries[0];
  assert.equal(e.previousPassword, 'old-pass');
  assert.equal(e.passwordUpdatedAt, 2000);
  assert.equal(e.changed, true);
  // パスワード以外の変更では前のパスワードは変わらない
  v = upsertEntry(v, { id: e.id, title: 'A2', password: 'new-pass', changed: true }, 3000).vault;
  e = v.entries[0];
  assert.equal(e.previousPassword, 'old-pass');
  assert.equal(e.passwordUpdatedAt, 2000);
  v = clearPreviousPassword(v, e.id, 4000);
  assert.equal('previousPassword' in v.entries[0], false);
  assert.ok(v.entries[0].updatedAt >= 4000);
  // 削除すると前のパスワードも残らない
  v = upsertEntry(v, { id: e.id, title: 'A2', password: 'third', changed: true }, 5000).vault;
  v = deleteEntry(v, e.id, 6000);
  assert.equal(v.entries[0].previousPassword, undefined);
});

test('使い回し・弱いパスワードの検出と絞り込み', () => {
  let v = createVault();
  v = upsertEntry(v, { title: 'A', password: 'password1' }).vault;
  v = upsertEntry(v, { title: 'B', password: 'password1' }).vault;
  v = upsertEntry(v, { title: 'C', password: generatePassword({ length: 20 }), changed: true }).vault;
  v = upsertEntry(v, { title: 'D', password: '' }).vault;
  const list = liveEntries(v);
  const issues = passwordIssues(list);
  const byTitle = Object.fromEntries(list.map((e) => [e.title, issues.get(e.id)]));
  assert.deepEqual(byTitle.A, { reused: true, weak: true });
  assert.deepEqual(byTitle.C, { reused: false, weak: false });
  assert.deepEqual(byTitle.D, { reused: false, weak: false });
  const titles = (f) => filterEntries(list, f, issues).map((e) => e.title);
  assert.deepEqual(titles('done'), ['C']);
  assert.deepEqual(titles('todo'), ['A', 'B', 'D']);
  assert.deepEqual(titles('risk'), ['A', 'B']);
  assert.equal(titles('all').length, 4);
});

test('追加項目の型が違うデータは拒否', () => {
  const ok = { id: 'a', updatedAt: 1, title: 't', username: '', password: '', url: '', notes: '' };
  assert.doesNotThrow(() => validateVault({ entries: [{ ...ok, changed: true, previousPassword: 'x', passwordUpdatedAt: 5 }] }));
  assert.throws(() => validateVault({ entries: [{ ...ok, changed: 'yes' }] }));
  assert.throws(() => validateVault({ entries: [{ ...ok, previousPassword: 1 }] }));
});
