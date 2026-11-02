/**
 * @file opcode-tables.js
 * @description Dynamic Opcode Permutation Generator
 * @source Extracted from index-993d072d.js (offsets ~27500 - 32500)
 *
 * MooMoo.io scrambles all client-to-server and server-to-client packet opcodes
 * dynamically per session connection to prevent bots from sending or listening
 * for fixed string packet identifiers.
 *
 * It uses:
 * 1. Mulberry32 32-bit PRNG (Bx)
 * 2. Fisher-Yates shuffle (ka)
 * 3. FNV-1a collision-resolving hash permutation (s0)
 * 4. Combined salt hashing (c0)
 */

/**
 * Base list of 22 Client-to-Server (c2s) packet action identifiers.
 * Original array: `cc`
 *
 * Typical meanings in legacy MooMoo protocol:
 * - "M": Player spawn request {name, skin, moofoll}
 * - "D": Movement direction / mouse angle
 * - "0": Ping keepalive
 * - "c": Chat message
 * - "6": Upgrade selection
 * - "z": Buy item from shop
 * - "K": Equip item (hat / accessory)
 * - "e": Auto-attack toggle
 * - "b": Clan action (create/join/leave)
 */
export const CLIENT_OPCODES = [
    "M", "D", "9", "e", "F", "z", "H", "K", "L", "N",
    "b", "P", "Q", "c", "6", "S", "0", "T", "R", "A", "V", "I"
];

/**
 * Base list of 42 Server-to-Client (s2c) packet event identifiers.
 * Original array: `rc`
 *
 * Typical meanings in legacy MooMoo protocol:
 * - "io-init": Secure handshake initialization
 * - "0": Pong keepalive response
 * - "A": Team / clan roster update
 * - "C": Player entity ID assignment
 * - "D": Player spawn / setup confirmation
 * - "H": Visible game objects (trees, rocks, buildings)
 * - "a": Entity movement & delta positions
 * - "G": Leaderboard sync
 * - "7": Player points / gold update
 * - "p": Player damage / health update
 */
export const SERVER_OPCODES = [
    "A", "B", "C", "D", "E", "a", "G", "H", "I", "J",
    "K", "L", "M", "N", "O", "P", "Q", "R", "S", "T",
    "U", "V", "X", "Y", "Z", "g", "1", "2", "3", "4",
    "5", "6", "7", "8", "9", "0", "W", "F", "p", "q", "r", "m"
];

/**
 * Creates a Mulberry32 32-bit pseudo-random number generator function.
 * Original function name: `Bx(e)`
 *
 * @param {number} seed - 32-bit integer seed.
 * @returns {() => number} Function returning a float in range [0, 1).
 */
export function createMulberry32(seed) {
    let s = seed | 0;
    return function () {
        s |= 0;
        s = (s + 1831565813) | 0; // 0x6D2B79F5
        let a = Math.imul(s ^ (s >>> 15), 1 | s);
        a = (a + Math.imul(a ^ (a >>> 7), 61 | a)) ^ a;
        return ((a ^ (a >>> 14)) >>> 0) / 4294967296;
    };
}

/**
 * Shuffles an array of opcode names using the Fisher-Yates algorithm
 * driven by a Mulberry32 PRNG instance.
 * Original function name: `ka(e, t)`
 *
 * @param {string[]} opcodes - Array of opcode strings to shuffle.
 * @param {number} seed - 32-bit integer seed for Mulberry32.
 * @returns {{ enc: Record<string, number>, dec: Record<number, string> }}
 */
export function fisherYatesShuffle(opcodes, seed) {
    const len = opcodes.length;
    const indices = opcodes.map((_, i) => i);
    const rng = createMulberry32(seed >>> 0);

    for (let i = len - 1; i > 0; i--) {
        const j = Math.floor(rng() * (i + 1));
        const temp = indices[i];
        indices[i] = indices[j];
        indices[j] = temp;
    }

    const enc = {};
    const dec = {};
    for (let i = 0; i < len; i++) {
        enc[opcodes[i]] = indices[i];
        dec[indices[i]] = opcodes[i];
    }

    return { enc, dec };
}

/**
 * Extends the shuffle tables by generating pseudo-random index mappings
 * using 32-bit FNV-1a hash distribution with linear probing collision resolution.
 * Original function name: `s0(e, t, n, o)`
 *
 * @param {{ enc: Record<string, number>, dec: Record<number, string> }} tables - Existing tables.
 * @param {string[]} fullArray - Opcode array.
 * @param {number} offset - Boundary offset (22 for c2s, 39 for s2c).
 * @param {number} seed - Hash seed.
 * @returns {{ enc: Record<string, number>, dec: Record<number, string> }} Updated tables.
 */
export function fnvHashPermute(tables, fullArray, offset, seed) {
    const totalSlots = 128 - offset; // Max opcode id is 127
    const occupied = {};

    for (let i = offset; i < fullArray.length; i++) {
        const op = fullArray[i];
        let hash = (2166136261 ^ seed) >>> 0;

        for (let j = 0; j < op.length; j++) {
            hash = Math.imul(hash ^ (op.charCodeAt(j) & 255), 16777619);
        }

        hash ^= (hash >>> 16);
        hash = Math.imul(hash, 739982445);
        hash ^= (hash >>> 12);

        let slot = (hash >>> 0) % totalSlots;
        // Linear probing collision resolution
        while (occupied[slot]) {
            slot = (slot + 1) % totalSlots;
        }
        occupied[slot] = true;

        const mappedId = offset + slot;
        tables.enc[op] = mappedId;
        tables.dec[mappedId] = op;
    }

    return tables;
}

/**
 * Constructs the complete session opcode lookup tables for bidirectional packet translation.
 * Original function name: `c0(e, t)`
 *
 * Salt combination formulas:
 *   Knuth multiplier: 2654435761 (0x9E3779B9)
 *   Murmur constant:  2246822507 (0x85EBCA6B)
 *
 *   s = (seedA ^ Math.imul(buildSalt, 0x9E3779B9)) >>> 0
 *   c = (s ^ 0x85EBCA6B) >>> 0
 *
 * @param {number} seedA - 32-bit timestamp/random seed received in `io-init`.
 * @param {number} [buildSalt=2988461847] - BUILD_SALT constant from moomoo-protocol.
 * @returns {{
 *   c2s: { enc: Record<string, number>, dec: Record<number, string> },
 *   s2c: { enc: Record<string, number>, dec: Record<number, string> }
 * }}
 */
export function generateSessionOpcodeTables(seedA, buildSalt = 2988461847) {
    const salt = buildSalt ?? 2;
    // Multiplicative hash combining seedA and buildSalt
    const s = (seedA ^ Math.imul(salt, 2654435761)) >>> 0;
    // XOR inversion constant for the server-to-client table
    const c = (s ^ 2246822507) >>> 0;

    return {
        c2s: fnvHashPermute(
            fisherYatesShuffle(CLIENT_OPCODES.slice(0, 22), s),
            CLIENT_OPCODES,
            22,
            s
        ),
        s2c: fnvHashPermute(
            fisherYatesShuffle(SERVER_OPCODES.slice(0, 39), c),
            SERVER_OPCODES,
            39,
            c
        )
    };
}
