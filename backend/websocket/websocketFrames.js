/**
 * WebSocket Frame Codec — Phase 2
 * WebVitals
 *
 * RFC 6455-compliant minimal framing for server-side WebSocket.
 * Handles: text frames, close frames, ping, pong, masked client frames.
 *
 * This module is intentionally isolated from application logic.
 * It knows nothing about scans, scanIds, or progress events.
 */

'use strict';

const crypto = require('crypto');

// ─── RFC 6455 Constants ───────────────────────────────────────────────────────
const WS_MAGIC   = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';
const OPCODES    = { CONTINUATION: 0x0, TEXT: 0x1, BINARY: 0x2, CLOSE: 0x8, PING: 0x9, PONG: 0xA };
const MAX_PAYLOAD_SAFE = 1 * 1024 * 1024; // 1 MB max inbound payload

// ─── Handshake ────────────────────────────────────────────────────────────────

/**
 * Generates the Sec-WebSocket-Accept header value.
 * SHA-1( key + MAGIC ) → base64
 */
function generateAcceptKey(clientKey) {
  return crypto
    .createHash('sha1')
    .update(clientKey + WS_MAGIC)
    .digest('base64');
}

/**
 * Validates an HTTP upgrade request for WebSocket compatibility.
 * Returns { valid: boolean, reason?: string, key?: string }
 */
function validateUpgradeRequest(req) {
  if (req.method !== 'GET') {
    return { valid: false, reason: 'WebSocket upgrade requires GET method' };
  }
  const upgrade = (req.headers.upgrade || '').toLowerCase();
  if (upgrade !== 'websocket') {
    return { valid: false, reason: 'Upgrade header must be "websocket"' };
  }
  const version = req.headers['sec-websocket-version'];
  if (version !== '13') {
    return { valid: false, reason: `Unsupported WebSocket version: ${version}. Expected 13` };
  }
  const key = req.headers['sec-websocket-key'];
  if (!key || key.trim().length === 0) {
    return { valid: false, reason: 'Missing Sec-WebSocket-Key header' };
  }
  return { valid: true, key: key.trim() };
}

/**
 * Writes the 101 Switching Protocols response.
 */
function writeHandshakeResponse(socket, clientKey) {
  const acceptKey = generateAcceptKey(clientKey);
  const response = [
    'HTTP/1.1 101 Switching Protocols',
    'Upgrade: websocket',
    'Connection: Upgrade',
    `Sec-WebSocket-Accept: ${acceptKey}`,
    '',
    '',
  ].join('\r\n');
  socket.write(response);
}

// ─── Frame encoder (server → client) ─────────────────────────────────────────
// Server MUST NOT mask frames sent to client (RFC 6455 §5.1)

/**
 * Encode a text frame.
 */
function encodeTextFrame(text) {
  const payload = Buffer.from(text, 'utf8');
  return _encodeFrame(OPCODES.TEXT, payload);
}

/**
 * Encode a close frame.
 * @param {number} [code=1000]
 * @param {string} [reason='']
 */
function encodeCloseFrame(code = 1000, reason = '') {
  const reasonBuf = Buffer.from(reason, 'utf8');
  const payload = Buffer.allocUnsafe(2 + reasonBuf.length);
  payload.writeUInt16BE(code, 0);
  reasonBuf.copy(payload, 2);
  return _encodeFrame(OPCODES.CLOSE, payload);
}

/**
 * Encode a ping frame.
 */
function encodePingFrame(data = '') {
  return _encodeFrame(OPCODES.PING, Buffer.from(data));
}

/**
 * Encode a pong frame.
 */
function encodePongFrame(data = '') {
  return _encodeFrame(OPCODES.PONG, Buffer.from(data));
}

function _encodeFrame(opcode, payload) {
  const len = payload.length;
  let header;

  if (len < 126) {
    header = Buffer.allocUnsafe(2);
    header[0] = 0x80 | opcode; // FIN + opcode
    header[1] = len;
  } else if (len < 65536) {
    header = Buffer.allocUnsafe(4);
    header[0] = 0x80 | opcode;
    header[1] = 126;
    header.writeUInt16BE(len, 2);
  } else {
    header = Buffer.allocUnsafe(10);
    header[0] = 0x80 | opcode;
    header[1] = 127;
    // Node.js doesn't support BigInt writes on all versions — write as two 32-bit ints
    header.writeUInt32BE(0, 2);
    header.writeUInt32BE(len, 6);
  }

  return Buffer.concat([header, payload]);
}

// ─── Frame decoder (client → server) ─────────────────────────────────────────
// Client MUST mask frames sent to server (RFC 6455 §5.1)

/**
 * Parse incoming WebSocket frames from a Buffer.
 * Returns { frames: ParsedFrame[], remainder: Buffer }
 *
 * ParsedFrame: { opcode, payload: Buffer, fin: boolean }
 */
function parseFrames(buf) {
  const frames = [];
  let offset = 0;

  while (offset < buf.length) {
    if (buf.length - offset < 2) break; // not enough header bytes yet

    const byte1  = buf[offset];
    const byte2  = buf[offset + 1];
    const fin    = !!(byte1 & 0x80);
    const opcode = byte1 & 0x0F;
    const masked = !!(byte2 & 0x80);
    let payloadLen = byte2 & 0x7F;

    let headerLen = 2;

    if (payloadLen === 126) {
      if (buf.length - offset < 4) break;
      payloadLen = buf.readUInt16BE(offset + 2);
      headerLen  = 4;
    } else if (payloadLen === 127) {
      if (buf.length - offset < 10) break;
      // 8-byte payload length — only read lower 4 bytes (safe for ≤4GB)
      payloadLen = buf.readUInt32BE(offset + 6);
      headerLen  = 10;
    }

    // Safety check
    if (payloadLen > MAX_PAYLOAD_SAFE) {
      throw Object.assign(new Error('WebSocket frame payload too large'), { code: 'WS_PAYLOAD_TOO_LARGE' });
    }

    const maskLen  = masked ? 4 : 0;
    const totalLen = headerLen + maskLen + payloadLen;

    if (buf.length - offset < totalLen) break; // incomplete frame

    let payload = buf.slice(offset + headerLen + maskLen, offset + totalLen);

    if (masked) {
      const mask    = buf.slice(offset + headerLen, offset + headerLen + 4);
      const unmasked = Buffer.allocUnsafe(payloadLen);
      for (let i = 0; i < payloadLen; i++) {
        unmasked[i] = payload[i] ^ mask[i % 4];
      }
      payload = unmasked;
    }

    frames.push({ opcode, payload, fin });
    offset += totalLen;
  }

  return { frames, remainder: buf.slice(offset) };
}

module.exports = {
  OPCODES,
  generateAcceptKey,
  validateUpgradeRequest,
  writeHandshakeResponse,
  encodeTextFrame,
  encodeCloseFrame,
  encodePingFrame,
  encodePongFrame,
  parseFrames,
  MAX_PAYLOAD_SAFE,
};
