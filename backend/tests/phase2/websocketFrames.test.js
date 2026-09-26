/**
 * WebSocket Frames & Codec Tests — Phase 2
 * WebVitals
 *
 * Tests RFC 6455 framing, encoding, decoding, masking, accept key generation.
 * Run: node --test backend/tests/phase2/websocketFrames.test.js
 */

'use strict';

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const {
  generateAcceptKey,
  validateUpgradeRequest,
  encodeTextFrame,
  encodeCloseFrame,
  encodePingFrame,
  encodePongFrame,
  parseFrames,
  OPCODES,
} = require('../../websocket/websocketFrames');

describe('WebSocket Handshake Validation & Key Generation', () => {
  test('generateAcceptKey creates valid RFC 6455 Sec-WebSocket-Accept token', () => {
    // Example from RFC 6455 spec:
    // Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
    // Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=
    const key = 'dGhlIHNhbXBsZSBub25jZQ==';
    const accept = generateAcceptKey(key);
    assert.strictEqual(accept, 's3pPLMBiTxaQ9kYGzzhZRbK+xOo=');
  });

  test('validateUpgradeRequest validates HTTP GET with required headers', () => {
    const validReq = {
      method: 'GET',
      headers: {
        upgrade: 'websocket',
        'sec-websocket-version': '13',
        'sec-websocket-key': 'dGhlIHNhbXBsZSBub25jZQ==',
      },
    };
    const res = validateUpgradeRequest(validReq);
    assert.strictEqual(res.valid, true);
    assert.strictEqual(res.key, 'dGhlIHNhbXBsZSBub25jZQ==');
  });

  test('validateUpgradeRequest rejects non-GET methods', () => {
    const postReq = {
      method: 'POST',
      headers: { upgrade: 'websocket', 'sec-websocket-version': '13', 'sec-websocket-key': 'abc' },
    };
    const res = validateUpgradeRequest(postReq);
    assert.strictEqual(res.valid, false);
    assert.match(res.reason, /GET/);
  });

  test('validateUpgradeRequest rejects unsupported version', () => {
    const badVer = {
      method: 'GET',
      headers: { upgrade: 'websocket', 'sec-websocket-version': '12', 'sec-websocket-key': 'abc' },
    };
    const res = validateUpgradeRequest(badVer);
    assert.strictEqual(res.valid, false);
    assert.match(res.reason, /Unsupported WebSocket version/);
  });
});

describe('WebSocket Frame Encoding (Server -> Client, unmasked)', () => {
  test('encodeTextFrame encodes short text frame (<126 bytes)', () => {
    const text = 'Hello, WebVitals!';
    const buf = encodeTextFrame(text);

    // FIN + Opcode text (0x81)
    assert.strictEqual(buf[0], 0x81);
    // Unmasked, len = Buffer.byteLength(text)
    assert.strictEqual(buf[1], Buffer.byteLength(text));
    assert.strictEqual(buf.slice(2).toString('utf8'), text);
  });

  test('encodeTextFrame encodes medium text frame (126-65535 bytes)', () => {
    const payload = 'A'.repeat(300);
    const buf = encodeTextFrame(payload);

    assert.strictEqual(buf[0], 0x81);
    assert.strictEqual(buf[1], 126);
    assert.strictEqual(buf.readUInt16BE(2), 300);
    assert.strictEqual(buf.slice(4).toString('utf8'), payload);
  });

  test('encodeCloseFrame encodes 1000 Normal Closure with reason', () => {
    const buf = encodeCloseFrame(1000, 'Goodbye');
    assert.strictEqual(buf[0], 0x80 | OPCODES.CLOSE);
    const len = buf[1];
    assert.strictEqual(len, 2 + 7); // 2 bytes code + 7 bytes reason
    assert.strictEqual(buf.readUInt16BE(2), 1000);
    assert.strictEqual(buf.slice(4).toString('utf8'), 'Goodbye');
  });

  test('encodePingFrame and encodePongFrame encode correct opcodes', () => {
    const ping = encodePingFrame('ping-test');
    assert.strictEqual(ping[0], 0x80 | OPCODES.PING);

    const pong = encodePongFrame('pong-test');
    assert.strictEqual(pong[0], 0x80 | OPCODES.PONG);
  });
});

describe('WebSocket Frame Decoding (Client -> Server, masked)', () => {
  function createMaskedFrame(opcode, text) {
    const payload = Buffer.from(text, 'utf8');
    const mask = Buffer.from([0x12, 0x34, 0x56, 0x78]);
    const maskedPayload = Buffer.alloc(payload.length);
    for (let i = 0; i < payload.length; i++) {
      maskedPayload[i] = payload[i] ^ mask[i % 4];
    }

    const header = Buffer.alloc(2 + 4);
    header[0] = 0x80 | opcode;
    header[1] = 0x80 | payload.length; // Masked bit set
    mask.copy(header, 2);

    return Buffer.concat([header, maskedPayload]);
  }

  test('parseFrames parses single masked text frame', () => {
    const originalText = '{"type":"SUBSCRIBE","scanId":"1234"}';
    const clientFrame = createMaskedFrame(OPCODES.TEXT, originalText);

    const { frames, remainder } = parseFrames(clientFrame);
    assert.strictEqual(frames.length, 1);
    assert.strictEqual(frames[0].opcode, OPCODES.TEXT);
    assert.strictEqual(frames[0].payload.toString('utf8'), originalText);
    assert.strictEqual(remainder.length, 0);
  });

  test('parseFrames handles partial frames and buffers remainder', () => {
    const originalText = '{"type":"PING"}';
    const fullFrame = createMaskedFrame(OPCODES.TEXT, originalText);

    // Split in half
    const part1 = fullFrame.slice(0, 5);
    const part2 = fullFrame.slice(5);

    const step1 = parseFrames(part1);
    assert.strictEqual(step1.frames.length, 0);
    assert.strictEqual(step1.remainder.length, 5);

    const step2 = parseFrames(Buffer.concat([step1.remainder, part2]));
    assert.strictEqual(step2.frames.length, 1);
    assert.strictEqual(step2.frames[0].payload.toString('utf8'), originalText);
    assert.strictEqual(step2.remainder.length, 0);
  });
});
