'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createAccountVault } = require('./account-vault.cjs');

function mockSafeStorage() {
  return {
    isEncryptionAvailable: () => true,
    encryptString: (s) => Buffer.from(`enc:${s}`),
    decryptString: (buf) => {
      const text = Buffer.from(buf).toString('utf8');
      assert.ok(text.startsWith('enc:'));
      return text.slice(4);
    },
  };
}

test('vault fails closed without encryption and never exposes plaintext API', () => {
  assert.throws(() => createAccountVault({ safeStorage: null, userDataPath: '/tmp', fs: {} }));
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mythos-vault-'));
  const vault = createAccountVault({
    safeStorage: mockSafeStorage(),
    userDataPath: dir,
    fs,
  });
  const ack = vault.putSecret('account_a', 's3cret-value');
  assert.equal(ack.alias, 'account_a');
  assert.equal(typeof vault.putSecret, 'function');
  assert.equal(typeof vault.readSecret, 'undefined');
  assert.deepEqual(vault.listAliases().map((x) => x.alias), ['account_a']);
  const disk = fs.readFileSync(vault.storePath, 'utf8');
  assert.equal(disk.includes('s3cret-value'), false);
  assert.equal(vault.materializeForInjection('account_a'), 's3cret-value');
});

test('vault reloads ciphertext after process restart simulation', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mythos-vault-'));
  const first = createAccountVault({
    safeStorage: mockSafeStorage(),
    userDataPath: dir,
    fs,
  });
  first.putSecret('account_b', 'persist-me');
  const second = createAccountVault({
    safeStorage: mockSafeStorage(),
    userDataPath: dir,
    fs,
  });
  assert.deepEqual(second.listAliases().map((x) => x.alias), ['account_b']);
  assert.equal(second.materializeForInjection('account_b'), 'persist-me');
  const raw = fs.readFileSync(second.storePath, 'utf8');
  assert.equal(raw.includes('persist-me'), false);
});

test('vault rejects unsafe aliases and fails closed on corrupt ciphertext store', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mythos-vault-'));
  const vault = createAccountVault({ safeStorage: mockSafeStorage(), userDataPath: dir, fs });
  assert.throws(() => vault.putSecret('../account', 'secret'), /invalid_account_alias/);
  fs.writeFileSync(vault.storePath, '{not-json', 'utf8');
  assert.throws(
    () => createAccountVault({ safeStorage: mockSafeStorage(), userDataPath: dir, fs }),
    /vault_corrupt/,
  );
});

test('vault writes atomically with restrictive mode and leaves no temporary file', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mythos-vault-'));
  const vault = createAccountVault({ safeStorage: mockSafeStorage(), userDataPath: dir, fs });
  vault.putSecret('account_a', 'secret');
  assert.equal(fs.existsSync(`${vault.storePath}.tmp`), false);
  if (process.platform !== 'win32') {
    assert.equal(fs.statSync(vault.storePath).mode & 0o077, 0);
  }
});
