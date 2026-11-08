// The identification key (INT-11.6, INT-01.28): one X25519 key pair per browser
// profile, made the first time it is needed after a hello, kept as one record in
// IndexedDB (database "bridge", store "keys", key "identification"). CryptoKey
// objects are serializable, so IndexedDB keeps them without their bytes ever
// reaching script; the private key cannot be exported. The key never goes into
// storage.local, a message to a content script or frame, a log or a page.

import { keyPair } from './channel.js';

const DATABASE = 'bridge';
const STORE = 'keys';
const RECORD = 'identification';

function database() {
  return new Promise((resolve, reject) => {
    const asked = indexedDB.open(DATABASE, 1);
    asked.onupgradeneeded = () => asked.result.createObjectStore(STORE);
    asked.onsuccess = () => resolve(asked.result);
    asked.onerror = () => reject(asked.error);
  });
}

async function run(mode, act) {
  const db = await database();
  return new Promise((resolve, reject) => {
    const t = db.transaction(STORE, mode);
    const asked = act(t.objectStore(STORE));
    t.oncomplete = () => {
      db.close();
      resolve(asked.result);
    };
    t.onabort = () => {
      db.close();
      reject(t.error);
    };
  });
}

/** The identification CryptoKeyPair; made and stored when no record exists. */
export async function identification() {
  const kept = await run('readonly', (s) => s.get(RECORD));
  if (kept) return kept;
  const pair = await keyPair();
  // `add` never writes over a key another call stored first; that one wins.
  await run('readwrite', (s) => s.add(pair, RECORD)).catch(() => {});
  return run('readonly', (s) => s.get(RECORD));
}
