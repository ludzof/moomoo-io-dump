/**
 * @file moomoo-seal.js
 * @description Deobfuscated & Fully Annotated "MooMoo Seal" Anti-Tamper & Network Subsystem
 * @source Extracted from index-993d072d.js (offsets ~52000 - 58500)
 *
 * "MooMoo Seal" is the client-side defense and secure transport layer in MooMoo.io:
 * 1. Self-Bundle Integrity Verification (SHA-256 Checksum)
 * 2. Function Hook / Monkeypatch Detection
 * 3. Secure WebSocket Framing, Signing, and Encryption
 */

import { BUILD_ID, BUILD_SALT, mixKey } from "./moomoo-protocol.js";
import {
    hexToBytes,
    readUint32LE,
    xorshiftEncrypt,
    deriveStreamMasks,
    getS2CKeystreamSeed,
    getC2SKeystreamSeed,
    updateLedger,
    computePacketTag,
    computeSealCheck,
    TAG_LENGTH,
    INITIAL_LEDGER
} from "./crypto-primitives.js";
import { generateSessionOpcodeTables } from "./opcode-tables.js";

/**
 * MessagePack encoder and decoder instances (from vendor bundle or @msgpack/msgpack).
 */
import { E as MsgPackEncoder, D as MsgPackDecoder } from "../../raw/vendor-a3a301f0.js";

const encoder = new MsgPackEncoder();
const decoder = new MsgPackDecoder();

/**
 * Cached bundle integrity data.
 * @type {{ digest: Uint8Array, text: string } | null}
 */
export let bundleIntegrity = null;

/**
 * Self-Bundle Integrity Initialization.
 * Asynchronously fetches the bundle's own JavaScript file via `fetch(import.meta.url)`
 * and computes its SHA-256 digest.
 */
export async function initBundleIntegrity() {
    if (typeof fetch === "undefined" || !import.meta.url) return;
    try {
        const response = await fetch(import.meta.url);
        const arrayBuffer = await response.arrayBuffer();
        const hashBuffer = await crypto.subtle.digest("SHA-256", arrayBuffer);

        bundleIntegrity = {
            // First 16 bytes of SHA-256 digest
            digest: new Uint8Array(hashBuffer).subarray(0, 16),
            text: new TextDecoder().decode(arrayBuffer)
        };
    } catch (err) {
        console.warn("Bundle integrity check failed to initialize:", err);
    }
}

/**
 * Guarded functions list registered via H.guard().
 * @type {Function[]}
 */
const guardedFunctions = [];

/**
 * Hook / Tampering Verification Routine.
 * Original function name: `Cd(e)`
 *
 * Inspects the browser DOM importmap for "moomoo-seal":
 *   `<script type="importmap">{"imports":{"moomoo-seal":"/p/<32-hex-hash>.js"}}</script>`
 *
 * Verifies that critical functions (such as socket.send and socket.connect)
 * have NOT been wrapped, overridden, or hooked by userscripts:
 *   Function.prototype.toString.call(fn) must exist verbatim in original bundle source code.
 *
 * If tampering is detected, key `s` is deliberately corrupted by XORing with 165,
 * causing all subsequent packet encryption to produce garbage data that the server rejects.
 *
 * @param {Function[]} functionsToVerify - Functions to verify against tampering.
 * @returns {Uint8Array | null} 16-byte seal key X, or null.
 */
export function verifyFunctionIntegrity(functionsToVerify) {
    try {
        if (typeof document === "undefined") return null;

        const importMapElement = document.querySelector('script[type="importmap"]');
        if (!importMapElement) return null;

        const imports = JSON.parse(importMapElement.textContent).imports;
        const sealUrl = imports["moomoo-seal"];
        const match = /([0-9a-f]{32})\.js$/.exec(sealUrl);
        if (!match || !bundleIntegrity) return null;

        const sealKey = hexToBytes(match[1]);
        const allFunctions = functionsToVerify.concat(guardedFunctions);

        // Check if toString() of each function is found unchanged in original script text
        const isUntampered = allFunctions.every(fn => {
            const fnSource = Function.prototype.toString.call(fn);
            return bundleIntegrity.text.indexOf(fnSource) !== -1;
        });

        for (let i = 0; i < sealKey.length; i++) {
            // If untampered, (isUntampered ? 0 : 165) is 0
            // If hooked, XORs with 165, fatally corrupting the session key
            sealKey[i] ^= bundleIntegrity.digest[i] ^ (isUntampered ? 0 : 165);
        }

        return sealKey;
    } catch {
        return null;
    }
}

/**
 * Active session state object.
 * Original variable: `le`
 */
export let sessionState = null;

/**
 * Secure WebSocket Network Manager.
 * Original object: `H`
 */
export const NetworkManager = {
    socket: null,
    connected: false,
    socketId: -1,
    pinned: false,

    /**
     * Registers additional sensitive functions to be monitored by verifyFunctionIntegrity.
     * @param {...Function} fns
     */
    guard(...fns) {
        guardedFunctions.push(...fns);
    },

    /**
     * Returns the 32-bit session seal validation number.
     * @returns {number | null}
     */
    seal() {
        return sessionState && sessionState.seal !== undefined ? sessionState.seal : null;
    },

    /**
     * Returns the current outgoing sequence counter and rolling ledger hash.
     * @returns {[number, number] | null}
     */
    ledger() {
        return sessionState ? [sessionState.seq, sessionState.ledger] : null;
    },

    /**
     * Connects to a MooMoo.io edge game server over WebSocket.
     *
     * Appends query parameters:
     * - `b=<BUILD_ID>` (e.g. `b=s16prw`)
     * - `u=<BUNDLE_NAME>` (e.g. `u=index-993d072d`)
     *
     * @param {string} url - WebSocket server URL (e.g. wss://mem-dbxzm-tqmwl.eu.moomoo.io/?token=...)
     * @param {() => void} onOpen - Connection established callback.
     * @param {Record<string, Function>} packetHandlers - Map of opcode handlers.
     */
    connect(url, onOpen, packetHandlers) {
        if (this.socket) return;

        // Append b=BUILD_ID and u=BUNDLE_NAME to query string
        const separator = url.indexOf("?") === -1 ? "?" : "&";
        url += `${separator}b=${BUILD_ID}&u=index-993d072d`;

        const self = this;
        let isError = false;
        const ws = (this.socket = new WebSocket(url));
        ws.binaryType = "arraybuffer";

        ws.onopen = function () {
            self.connected = true;
            if (onOpen) onOpen();
        };

        ws.onmessage = function (event) {
            let buffer = new Uint8Array(event.data);

            // If session mask is initialized, decrypt incoming server packet in place
            if (sessionState && sessionState.mask) {
                const s2cSeed = getS2CKeystreamSeed(
                    sessionState.mask.s2c,
                    ++sessionState.received
                );
                xorshiftEncrypt(buffer, s2cSeed);
            }

            const message = decoder.decode(buffer);
            const opcode = message[0];
            const data = message[1];

            // Handle unencrypted initial handshake packet: "io-init"
            if (opcode === "io-init") {
                self.socketId = data[0];
                const mode = data[3];
                const isPinned = (self.pinned = data[4] === 1);

                if (mode === 1) {
                    const seedA = data[1] >>> 0;
                    const saltBytes = hexToBytes(data[2]);

                    // Step 1: Base session key via WebAssembly mixer
                    let masterKey = isPinned ? mixKey(saltBytes, seedA) : saltBytes;

                    // Step 2: Integrity check
                    const sealKey = isPinned && data[5] ? verifyFunctionIntegrity([self.send, self.connect]) : null;

                    // If data[5] === 2, masterKey is XOR'd with sealKey (in standard sessions data[5] === 1)
                    if (sealKey && data[5] === 2) {
                        masterKey = masterKey.map((b, idx) => b ^ sealKey[idx]);
                    }

                    // Step 3: Initialize session state
                    sessionState = {
                        seal: sealKey ? computeSealCheck(sealKey, seedA) : undefined,
                        mode: 1,
                        key: masterKey,
                        tables: generateSessionOpcodeTables(seedA, BUILD_SALT),
                        seq: 0,
                        ledger: INITIAL_LEDGER,
                        mask: isPinned ? deriveStreamMasks(masterKey) : null,
                        received: 0
                    };
                }
                return;
            }

            // Translate scrambled numerical opcode back to original action string
            let resolvedOpcode = opcode;
            if (sessionState && typeof opcode === "number") {
                resolvedOpcode = sessionState.tables.s2c.dec[opcode];
                if (resolvedOpcode === undefined) return;
            }

            // Dispatch to registered event handler
            const handler = packetHandlers[resolvedOpcode];
            if (handler) {
                handler.apply(undefined, data);
            }
        };

        ws.onclose = function () {
            self.connected = false;
            sessionState = null;
            self.socket = null;
        };

        ws.onerror = function () {
            isError = true;
        };
    },

    /**
     * Encodes, signs, encrypts, and transmits an outgoing packet to the game server.
     *
     * Wire Framing:
     *   [HMAC_TAG (6 bytes)] + [XORSHIFT32_ENCRYPTED_MSGPACK_PAYLOAD]
     *
     * Payload Structure:
     *   [scrambledOpcodeNumber, [arguments], sequenceNumber]
     *
     * @param {string} opcode - Action identifier (e.g. "M" for spawn, "D" for angle).
     * @param {...any} args - Action parameters.
     */
    send(opcode, ...args) {
        if (!this.socket) return;

        if (sessionState && sessionState.mode === 1) {
            // Translate action string to scrambled numerical opcode
            const scrambledOpcode = sessionState.tables.c2s.enc[opcode];
            if (scrambledOpcode === undefined) return;

            // Increment monotonic packet sequence counter
            const seq = ++sessionState.seq;

            // MessagePack payload: [opcode, arguments, sequence]
            const payload = encoder.encode([scrambledOpcode, args, seq]);

            // Update rolling FNV-1a sequence integrity ledger
            sessionState.ledger = updateLedger(sessionState.ledger, payload);

            // Compute 6-byte HMAC authentication tag
            const tag = computePacketTag(sessionState.key, payload);

            // Construct final wire frame
            const frame = new Uint8Array(TAG_LENGTH + payload.length);
            frame.set(tag, 0);
            frame.set(payload, TAG_LENGTH);

            // Encrypt payload in place using Xorshift32 seeded with c2s mask mixed with tag
            if (sessionState.mask) {
                const c2sSeed = getC2SKeystreamSeed(sessionState.mask.c2s, tag);
                xorshiftEncrypt(frame.subarray(TAG_LENGTH), c2sSeed);
            }

            // Send raw binary frame over WebSocket
            this.socket.send(frame);
            return;
        }

        // Unencrypted fallback
        const frame = encoder.encode([opcode, args]);
        this.socket.send(frame);
    },

    /**
     * Checks if the WebSocket connection is active and ready.
     * @returns {boolean}
     */
    socketReady() {
        return !!this.socket && this.connected;
    },

    /**
     * Closes the active WebSocket connection.
     */
    close() {
        if (this.socket) {
            this.socket.close();
            this.socket = null;
        }
        this.connected = false;
        sessionState = null;
    }
};
