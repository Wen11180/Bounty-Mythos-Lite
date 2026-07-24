'use strict';

/** Electron-main-only encrypted account vault. */

const path = require('node:path');

const SAFE_ALIAS = /^[a-z][a-z0-9_-]{0,31}$/;

function createAccountVault({ safeStorage, userDataPath, fs }) {
  if (
    !safeStorage ||
    typeof safeStorage.isEncryptionAvailable !== 'function' ||
    !safeStorage.isEncryptionAvailable() ||
    typeof safeStorage.encryptString !== 'function'
  ) {
    throw new Error('safe_storage_unavailable');
  }
  if (!userDataPath || typeof userDataPath !== 'string') {
    throw new Error('user_data_path_required');
  }
  if (
    !fs ||
    typeof fs.readFileSync !== 'function' ||
    typeof fs.writeFileSync !== 'function' ||
    typeof fs.renameSync !== 'function'
  ) {
    throw new Error('fs_required');
  }

  const storePath = path.join(userDataPath, 'autopilot-account-vault.json');
  const tempPath = `${storePath}.tmp`;
  /** @type {Map<string, { ciphertextB64: string, version: number }>} */
  const store = new Map();

  function requireAlias(alias) {
    if (typeof alias !== 'string' || !SAFE_ALIAS.test(alias)) {
      throw new Error('invalid_account_alias');
    }
    return alias;
  }

  function load() {
    if (!fs.existsSync(storePath)) return;
    let parsed;
    try {
      parsed = JSON.parse(fs.readFileSync(storePath, 'utf8'));
    } catch {
      throw new Error('vault_corrupt');
    }
    if (!parsed || parsed.schema !== 1 || !parsed.entries || typeof parsed.entries !== 'object') {
      throw new Error('vault_corrupt');
    }
    for (const [alias, entry] of Object.entries(parsed.entries)) {
      requireAlias(alias);
      if (
        !entry ||
        typeof entry.ciphertextB64 !== 'string' ||
        !Number.isSafeInteger(entry.version) ||
        entry.version < 1
      ) {
        throw new Error('vault_corrupt');
      }
      store.set(alias, {
        ciphertextB64: entry.ciphertextB64,
        version: entry.version,
      });
    }
  }

  function persist() {
    const entries = {};
    for (const alias of [...store.keys()].sort()) {
      const entry = store.get(alias);
      entries[alias] = {
        ciphertextB64: entry.ciphertextB64,
        version: entry.version,
      };
    }
    const payload = JSON.stringify({ schema: 1, entries });
    fs.mkdirSync(userDataPath, { recursive: true, mode: 0o700 });
    fs.writeFileSync(tempPath, payload, { encoding: 'utf8', mode: 0o600, flag: 'w' });
    if (typeof fs.chmodSync === 'function') fs.chmodSync(tempPath, 0o600);
    fs.renameSync(tempPath, storePath);
    if (typeof fs.chmodSync === 'function') fs.chmodSync(storePath, 0o600);
  }

  load();

  function putSecret(alias, plaintext) {
    const safeAlias = requireAlias(alias);
    if (typeof plaintext !== 'string' || plaintext.length === 0) {
      throw new Error('invalid_secret_entry');
    }
    const encrypted = safeStorage.encryptString(plaintext);
    if (!Buffer.isBuffer(encrypted) || encrypted.length === 0) {
      throw new Error('secret_encryption_failed');
    }
    const version = (store.get(safeAlias)?.version || 0) + 1;
    store.set(safeAlias, {
      ciphertextB64: encrypted.toString('base64'),
      version,
    });
    try {
      persist();
    } catch (error) {
      store.delete(safeAlias);
      throw error;
    }
    return { alias: safeAlias, version };
  }

  function hasAlias(alias) {
    return typeof alias === 'string' && store.has(alias);
  }

  function getAliasVersion(alias) {
    requireAlias(alias);
    return store.get(alias)?.version ?? null;
  }

  function listAliases() {
    return [...store.keys()].sort().map((alias) => ({
      alias,
      version: store.get(alias).version,
    }));
  }

  /** Main process only; the returned value must go directly to an owned context. */
  function materializeForInjection(alias) {
    const safeAlias = requireAlias(alias);
    const entry = store.get(safeAlias);
    if (!entry) throw new Error('alias_not_found');
    if (typeof safeStorage.decryptString !== 'function') {
      throw new Error('decrypt_unavailable');
    }
    return safeStorage.decryptString(Buffer.from(entry.ciphertextB64, 'base64'));
  }

  return {
    putSecret,
    hasAlias,
    getAliasVersion,
    listAliases,
    materializeForInjection,
    storePath,
  };
}

module.exports = { createAccountVault };
