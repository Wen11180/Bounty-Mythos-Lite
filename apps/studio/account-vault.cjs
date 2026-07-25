'use strict';

/**
 * Local encrypted account vault (Electron main only).
 * Secrets are encrypted with safeStorage and may be persisted as ciphertext.
 * No plaintext read API is exposed to the renderer.
 */

const path = require('node:path');

function createAccountVault({ safeStorage, userDataPath, fs }) {
  if (!safeStorage || typeof safeStorage.isEncryptionAvailable !== 'function') {
    throw new Error('safe_storage_unavailable');
  }
  if (!safeStorage.isEncryptionAvailable()) {
    throw new Error('safe_storage_unavailable');
  }
  if (typeof safeStorage.setUsePlainTextEncryption === 'function') {
    // Guard: never call setUsePlainTextEncryption
  }
  if (!userDataPath || typeof userDataPath !== 'string') {
    throw new Error('user_data_path_required');
  }
  if (!fs || typeof fs.readFileSync !== 'function' || typeof fs.writeFileSync !== 'function') {
    throw new Error('fs_required');
  }

  const storePath = path.join(userDataPath, 'autopilot-account-vault.json');
  /** @type {Map<string, { ciphertextB64: string, version: number }>} */
  const store = new Map();

  function load() {
    try {
      if (!fs.existsSync(storePath)) return;
      const raw = fs.readFileSync(storePath, 'utf8');
      const parsed = JSON.parse(raw);
      if (!parsed || typeof parsed !== 'object' || !parsed.entries) return;
      for (const [alias, entry] of Object.entries(parsed.entries)) {
        if (!entry || typeof entry.ciphertextB64 !== 'string') continue;
        store.set(alias, {
          ciphertextB64: entry.ciphertextB64,
          version: Number(entry.version) || 1,
        });
      }
    } catch {
      // Fail closed to empty in-memory state; do not throw on corrupt file at boot.
      store.clear();
    }
  }

  function persist() {
    const entries = {};
    for (const [alias, entry] of store.entries()) {
      entries[alias] = {
        ciphertextB64: entry.ciphertextB64,
        version: entry.version,
      };
    }
    const payload = JSON.stringify({ schema: 1, entries }, null, 0);
    fs.mkdirSync(userDataPath, { recursive: true });
    fs.writeFileSync(storePath, payload, 'utf8');
  }

  load();

  function putSecret(alias, plaintext) {
    if (!alias || typeof plaintext !== 'string') {
      throw new Error('invalid_secret_entry');
    }
    const encrypted = safeStorage.encryptString(plaintext);
    const ciphertextB64 = Buffer.isBuffer(encrypted)
      ? encrypted.toString('base64')
      : Buffer.from(String(encrypted)).toString('base64');
    const version = (store.get(alias)?.version || 0) + 1;
    store.set(alias, { ciphertextB64, version });
    persist();
    return { alias, version };
  }

  function hasAlias(alias) {
    return store.has(alias);
  }

  function listAliases() {
    return [...store.keys()].map((alias) => ({
      alias,
      version: store.get(alias).version,
    }));
  }

  /**
   * Main-process only: decrypt for owned Playwright injection.
   * Not exported through preload/renderer.
   */
  function materializeForInjection(alias) {
    const entry = store.get(alias);
    if (!entry) {
      throw new Error('alias_not_found');
    }
    if (typeof safeStorage.decryptString !== 'function') {
      throw new Error('decrypt_unavailable');
    }
    const buf = Buffer.from(entry.ciphertextB64, 'base64');
    return safeStorage.decryptString(buf);
  }

  return {
    putSecret,
    hasAlias,
    listAliases,
    materializeForInjection,
    userDataPath,
    storePath,
  };
}

module.exports = {
  createAccountVault,
};
