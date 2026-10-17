// ブラウザと同じく、Argon2 ライブラリを読み込むとグローバルの hashwasm が用意される
await import('../js/vendor/argon2.umd.min.js');
if (typeof globalThis.hashwasm?.argon2id !== 'function') throw new Error('hash-wasm を読み込めません');
