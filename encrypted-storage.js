/**
 * feve-encrypted-storage — Zero-knowledge, PIN-derived-key encrypted localStorage.
 * ---------------------------------------------------------------------------
 * AES encryption layer for browser localStorage with:
 *   • per-write random 128-bit IV (the same value never encrypts the same way twice)
 *   • PIN-derived key (SHA-256 of salt | 'PIN' | pin)
 *   • format-validated ciphertext  "hex(iv):AES-ciphertext"
 *   • graceful failures (null on encrypt problems, typed errors on decrypt)
 *
 * Production origin: the Feve app (com.femia.health) — a private, local-first
 * TTC companion where 100% of user data is encrypted on-device.
 * Site: https://feve.life · App: https://play.google.com/store/apps/details?id=com.femia.health
 *
 * Depends on: crypto-js (https://github.com/brix/crypto-js) — AES + SHA256 modules.
 * License: MIT — see LICENSE.
 */

(function (global) {
    'use strict';

    // Salt for PIN-derived keys. In a zero-knowledge setup the salt is NOT a
    // secret (there is no server); it exists only to make the mapping from a
    // PIN to a key app-specific. For multi-tenant/cloud uses, replace with a
    // per-user salt and stretch (see "Threat model" in the README).
    const KEY_SALT = 'fema-v1-salt-7e2b3c';

    /**
     * Derive an encryption key from a user PIN (6 digits in the Feve app).
     *
     * PIN-derived-key scheme: key = SHA256(salt | 'PIN' | pin). The same PIN
     * always rebuilds the same key — that is what lets the app decrypt its
     * data after a restart WITHOUT storing the key anywhere except a plain
     * localStorage slot the app manages out-of-band (see Feve's session code;
     * in this library the caller holds the resulting key string).
     *
     * NOTE: this is a fast hash — see the README "Threat model" section for
     * what that means and when it is (and is not) the right choice.
     *
     * @param {string} pin — the user's PIN (digits; any string accepted)
     * @returns {string|null} hex key string, or null if CryptoJS is missing
     */
    function derivePinKey(pin) {
        if (typeof CryptoJS === 'undefined') {
            console.error('CryptoJS not loaded');
            return null;
        }
        return CryptoJS.SHA256(KEY_SALT + '|PIN|' + pin).toString();
    }

    /**
     * Encrypt any JSON-serializable value under `key`.
     *
     * A fresh random 128-bit IV is generated for EVERY call — encrypting the
     * same payload twice produces different ciphertexts (semantic security).
     * Storage format:  hex(iv) + ':' + AES-ciphertext
     *
     * @param {*} data   — JSON-serializable value (null/undefined → null)
     * @param {string} key — the hex/string encryption key (see derivePinKey)
     * @returns {string|null} the composite encrypted string, or null on failure
     */
    function encryptData(data, key) {
        try {
            if (!data) return null;
            const iv = CryptoJS.lib.WordArray.random(128 / 8);
            const encrypted = CryptoJS.AES.encrypt(JSON.stringify(data), key, { iv: iv });
            if (!encrypted || !encrypted.toString()) {
                console.error('Encryption failed');
                return null;
            }
            return iv.toString() + ':' + encrypted.toString();
        } catch (error) {
            console.error('Encryption error:', error);
            return null;
        }
    }

    /**
     * Decrypt a string produced by encryptData back into the original value.
     *
     * Strict format validation up-front ("iv:ciphertext", exactly two parts),
     * then AES-decrypt with the parsed IV and JSON.parse the plaintext.
     * Throws typed, descriptive Errors — callers are expected to catch and
     * degrade gracefully (wrong key, tampered data, empty plaintext).
     *
     * @param {string} encryptedData — "hex(iv):AES-ciphertext"
     * @param {string} key — the same key used at encryption time
     * @returns {*} the original (JSON-parsed) value
     * @throws {Error} on bad format, wrong key, tampered/empty plaintext
     */
    function decryptData(encryptedData, key) {
        try {
            if (!encryptedData) throw new Error('No encrypted data provided');
            if (typeof encryptedData !== 'string' || !encryptedData.includes(':')) {
                throw new Error('Invalid encrypted data format');
            }
            const parts = encryptedData.split(':');
            if (parts.length !== 2) {
                throw new Error('Invalid encrypted data structure');
            }
            const iv = CryptoJS.enc.Hex.parse(parts[0]);
            const decrypted = CryptoJS.AES.decrypt(parts[1], key, { iv: iv });
            const decryptedString = decrypted.toString(CryptoJS.enc.Utf8);
            if (!decryptedString) {
                throw new Error('Decryption resulted in empty string');
            }
            return JSON.parse(decryptedString);
        } catch (error) {
            throw new Error('Decryption error: ' + error.message);
        }
    }

    // ─── localStorage convenience layer ────────────────────────────────────

    /**
     * Encrypt `data` under `key` and write it to localStorage[key].
     * This form takes the encryption key EXPLICITLY (zero-knowledge: the
     * caller owns the key lifecycle — e.g. deriving it from the PIN at
     * login); no key is stored or cached inside this module.
     *
     * @param {string} key     — localStorage slot name
     * @param {*}      data    — JSON-serializable payload
     * @param {string} encKey  — encryption key (see derivePinKey)
     */
    function saveEncryptedData(key, data, encKey) {
        const encrypted = encryptData(data, encKey);
        if (encrypted) {
            localStorage.setItem(key, encrypted);
        }
    }

    /**
     * Read localStorage[key] and decrypt it back into the original value.
     *
     * @param {string} key    — localStorage slot name
     * @param {string} encKey — the same key used when saving
     * @returns {*} the decrypted value, or null if missing/undecryptable
     *              (storage hiccup or wrong key — logged, non-throwing)
     */
    function loadEncryptedData(key, encKey) {
        const encrypted = localStorage.getItem(key);
        if (!encrypted) return null;
        try {
            return decryptData(encrypted, encKey);
        } catch (e) {
            console.warn('Failed to decrypt data for', key, ':', e.message);
            return null;
        }
    }

    // ─── Export ────────────────────────────────────────────────────────────
    global.FeveEncryptedStorage = {
        derivePinKey,
        encryptData,
        decryptData,
        saveEncryptedData,
        loadEncryptedData,
        // exposed for tests/custom salting
        KEY_SALT
    };

})(typeof window !== 'undefined' ? window : globalThis);