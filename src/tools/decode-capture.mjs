/**
 * @file decode-capture.mjs
 * @description Standalone tool to decrypt and inspect captured WebSocket packets from MooMoo.io HAR dumps.
 *
 * Usage:
 *   node src/tools/decode-capture.mjs [path_to_har_file]
 */

import fs from "fs";
import path from "path";
import { mixKey, BUILD_SALT } from "../protocol/moomoo-protocol.js";
import {
    hexToBytes,
    xorshiftEncrypt,
    deriveStreamMasks,
    getS2CKeystreamSeed,
    getC2SKeystreamSeed,
    TAG_LENGTH
} from "../protocol/crypto-primitives.js";
import { generateSessionOpcodeTables } from "../protocol/opcode-tables.js";
import { D as MsgPackDecoder } from "../../raw/vendor-a3a301f0.js";

const decoder = new MsgPackDecoder();

// Default HAR path
const harPath = process.argv[2] || path.resolve("dump/dump.har");

if (!fs.existsSync(harPath)) {
    console.error(`Error: File not found at ${harPath}`);
    process.exit(1);
}

console.log(`Parsing HAR archive: ${harPath}...`);
const har = JSON.parse(fs.readFileSync(harPath, "utf8"));
const entries = har.log.entries;

// Locate WebSocket entries
const wsEntries = entries.filter(e => e._webSocketMessages && e._webSocketMessages.length > 0);
console.log(`Found ${wsEntries.length} WebSocket session(s).`);

wsEntries.forEach((entry, sessionIndex) => {
    const url = entry.request.url;
    const messages = entry._webSocketMessages;
    console.log(`\n================================================================================`);
    console.log(`Session #${sessionIndex + 1}: ${url}`);
    console.log(`Total Frames: ${messages.length}`);
    console.log(`================================================================================\n`);

    let session = null;

    messages.forEach((msg, msgIndex) => {
        const rawBuffer = Buffer.from(msg.data, "base64");
        const packetBytes = new Uint8Array(rawBuffer);
        const direction = msg.type === "receive" ? "SERVER -> CLIENT" : "CLIENT -> SERVER";
        const dirSymbol = msg.type === "receive" ? "📥 [RECV]" : "📤 [SEND]";

        if (msg.type === "receive") {
            if (!session) {
                // Initial handshake packet ("io-init")
                try {
                    const decoded = decoder.decode(packetBytes);
                    const opcode = decoded[0];
                    const args = decoded[1];

                    if (opcode === "io-init") {
                        const socketId = args[0];
                        const seedA = args[1] >>> 0;
                        const saltHex = args[2];
                        const saltBytes = hexToBytes(saltHex);
                        const masterKey = mixKey(saltBytes, seedA);

                        session = {
                            socketId,
                            seedA,
                            masterKey,
                            tables: generateSessionOpcodeTables(seedA, BUILD_SALT),
                            mask: deriveStreamMasks(masterKey),
                            receivedCount: 0
                        };

                        console.log(`${dirSymbol} [Frame ${msgIndex}] HANDSHAKE: io-init`);
                        console.log(`   Socket ID : ${socketId}`);
                        console.log(`   Seed A    : ${seedA}`);
                        console.log(`   Salt Hex  : ${saltHex}`);
                        console.log(`   Master Key: ${Buffer.from(masterKey).toString("hex")}`);
                        console.log(`   -----------------------------------------------------------------------------`);
                        return;
                    }
                } catch (e) {
                    console.log(`${dirSymbol} [Frame ${msgIndex}] Failed to decode initial packet:`, e.message);
                    return;
                }
            }

            // Standard server-to-client frame: decrypt with s2c mask
            session.receivedCount++;
            const seed = getS2CKeystreamSeed(session.mask.s2c, session.receivedCount);
            xorshiftEncrypt(packetBytes, seed);

            try {
                const decoded = decoder.decode(packetBytes);
                const rawOpcode = decoded[0];
                const resolvedOpcode = session.tables.s2c.dec[rawOpcode] ?? `RAW_${rawOpcode}`;
                const payload = decoded[1];

                console.log(`${dirSymbol} [Frame ${msgIndex}] Opcode: '${resolvedOpcode}' (id=${rawOpcode})`);
                console.log(`   Payload: ${JSON.stringify(payload)}`);
            } catch (err) {
                console.log(`${dirSymbol} [Frame ${msgIndex}] Decrypt/Decode error: ${err.message}`);
            }
        } else if (msg.type === "send") {
            if (!session) {
                console.log(`${dirSymbol} [Frame ${msgIndex}] (Pre-handshake message, length=${packetBytes.length})`);
                return;
            }

            // Client-to-server frame: [6-byte tag] + [encrypted payload]
            const tag = packetBytes.subarray(0, TAG_LENGTH);
            const payloadBytes = new Uint8Array(packetBytes.subarray(TAG_LENGTH));

            const seed = getC2SKeystreamSeed(session.mask.c2s, tag);
            xorshiftEncrypt(payloadBytes, seed);

            try {
                const decoded = decoder.decode(payloadBytes);
                const rawOpcode = decoded[0];
                const resolvedOpcode = session.tables.c2s.dec[rawOpcode] ?? `RAW_${rawOpcode}`;
                const args = decoded[1];
                const seq = decoded[2];

                console.log(`${dirSymbol} [Frame ${msgIndex}] Opcode: '${resolvedOpcode}' (id=${rawOpcode}, seq=${seq})`);
                console.log(`   Tag : ${Buffer.from(tag).toString("hex")}`);
                console.log(`   Args: ${JSON.stringify(args)}`);
            } catch (err) {
                console.log(`${dirSymbol} [Frame ${msgIndex}] Decrypt/Decode error: ${err.message}`);
            }
        }
    });
});
console.log(`\nDecoding complete!`);
