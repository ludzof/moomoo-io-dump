/**
 * @file moomoo-protocol.js
 * @description Deobfuscated & Fully Annotated Protocol Security Module
 * @original_source /p/s16prw.js
 *
 * This module is dynamically mapped in the browser importmap:
 *   "moomoo-protocol": "/p/s16prw.js"
 *
 * It provides:
 * 1. BUILD_ID: Patch/security identifier ("s16prw") sent in the WebSocket URL query.
 * 2. BUILD_SALT: 32-bit integer constant (2988461847) used for opcode permutation.
 * 3. mixKey(): WebAssembly-accelerated byte-mixer used to scramble the initial session key.
 */

/**
 * Security build identifier sent to the game server in query parameter `b=<BUILD_ID>`.
 * @type {string}
 */
export const BUILD_ID = "s16prw";

/**
 * 32-bit integer salt constant used to seed the opcode permutation generator.
 * Calculated in original code via: (0xeb54 * 0x8588 + -0x259acd62 + 0xf * 0x632e597) >>> 0
 * Hex: 0xB227C097
 * @type {number}
 */
export const BUILD_SALT = 2988461847;

/**
 * Embedded WebAssembly binary (163 bytes) encoded in Base64.
 *
 * WebAssembly Disassembly:
 * - Module exports function `m(seed: i32, index: i32): i32`
 * - Implements a 32-bit integer mixing algorithm generating a deterministic
 *   keystream byte for any given (seed, byte_index) pair.
 * @type {string}
 */
const WASM_MIX_BYTECODE =
    "AGFzbQEAAAABBwFgAn9/AX8DAgEABwUBAW0AAAqGAQGDAQAgAUEBakGx893xeWwgAHMhACAAQQR3IQAg" +
    "AEHb9uLoemwhACAAIABBGXRzIQAgAEGqgbgdcyEAIABB46D+sgdqIQAgAEH8jPaGAnMhACAAQQ13IQAg" +
    "AEGX9oqBeWwhACAAQRB3IQAgAEGvi5usf3MhACAAQQ13IQAgAEELdkH/AXEL";

/**
 * Cached instance of the WebAssembly exported mixing function `m(seed, index)`.
 * @type {((seed: number, index: number) => number) | null}
 */
let wasmByteMixer = null;

/**
 * Lazy initializer for the WebAssembly mixing routine.
 * Compiles and instantiates the embedded WASM module synchronously on first call.
 *
 * @returns {(seed: number, index: number) => number} The WASM mixer function.
 */
function getByteMixer() {
    if (!wasmByteMixer) {
        // Decode base64 WebAssembly bytecode to Uint8Array
        let binaryString;
        if (typeof atob === "function") {
            binaryString = atob(WASM_MIX_BYTECODE);
        } else {
            binaryString = Buffer.from(WASM_MIX_BYTECODE, "base64").toString("binary");
        }

        const wasmBytes = new Uint8Array(binaryString.length);
        for (let i = 0; i < binaryString.length; i++) {
            wasmBytes[i] = binaryString.charCodeAt(i);
        }

        // Synchronously compile & instantiate WebAssembly module
        const wasmModule = new WebAssembly.Module(wasmBytes);
        const wasmInstance = new WebAssembly.Instance(wasmModule);

        // Function 'm' takes (seed: i32, index: i32) and returns an i32 byte value
        wasmByteMixer = wasmInstance.exports.m;
    }
    return wasmByteMixer;
}

/**
 * Symmetric WebAssembly-based XOR stream byte-mixer.
 *
 * Operation:
 *   For each byte i in input:
 *     output[i] = input[i] ^ wasm_m(seed | 0, i)
 *
 * Because XOR is strictly involutional (self-inverse):
 *   mixKey(mixKey(data, seed), seed) === data
 *
 * Used during the 'io-init' handshake to transform the session salt into the master key:
 *   J = mixKey(Sd(saltHex), seedA)
 *
 * @param {Uint8Array} buffer - Input byte buffer to transform.
 * @param {number} seed - 32-bit integer seed (seedA from 'io-init').
 * @returns {Uint8Array} Transformed (mixed or unmixed) byte array.
 */
export function mixKey(buffer, seed) {
    const mixer = getByteMixer();
    const result = new Uint8Array(buffer.length);
    const intSeed = seed | 0;

    for (let i = 0; i < buffer.length; i++) {
        result[i] = buffer[i] ^ mixer(intSeed, i);
    }

    return result;
}
