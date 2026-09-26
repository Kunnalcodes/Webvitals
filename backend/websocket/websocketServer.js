/**
 * WebSocket Server — Phase 2
 * WebVitals
 *
 * Native RFC 6455 WebSocket implementation on top of Node.js http.Server.
 * Zero external libraries (no ws, no socket.io).
 *
 * Features:
 *   - Native HTTP upgrade handling at /ws path (and /ws?scanId=...)
 *   - Protocol handshake with Sec-WebSocket-Accept
 *   - Safe frame parsing with payload protection
 *   - JSON message dispatch:
 *       Client -> Server: { type: 'SUBSCRIBE', scanId: '...' }
 *                         { type: 'UNSUBSCRIBE', scanId: '...' }
 *                         { type: 'PING' }
 *       Server -> Client: { type: 'SCAN_SNAPSHOT', ... }
 *                         { type: 'SCAN_PROGRESS', ... }
 *                         { type: 'SCAN_COMPLETE', ... }
 *                         { type: 'SCAN_ERROR', ... }
 *                         { type: 'PONG' }
 *   - Automatic subscription on initial connection if scanId is in query params
 *   - Periodic 30s heartbeat ping / liveness detection
 *   - Clean disconnect & resource teardown
 */

'use strict';

const { URL } = require('url');
const {
  validateUpgradeRequest,
  writeHandshakeResponse,
  encodeTextFrame,
  encodeCloseFrame,
  encodePingFrame,
  parseFrames,
  OPCODES,
} = require('./websocketFrames');
const { subscribe: subscribeProgress, emit: emitProgress } = require('../scan/progressEmitter');
const { getPublicState, buildEvent } = require('../scan/scanLifecycle');
const { scanRepository } = require('../storage/scanRepository');

// Keep-alive heartbeat interval (30s)
const HEARTBEAT_INTERVAL_MS = 30000;

/** @type {Set<object>} active client sessions */
const _clients = new Set();

/**
 * Send a structured JSON payload to a WebSocket client.
 *
 * @param {import('net').Socket} socket
 * @param {object} payload
 */
function sendJson(socket, payload) {
  if (!socket || socket.destroyed || !socket.writable) return;
  try {
    const text = JSON.stringify(payload);
    const frame = encodeTextFrame(text);
    socket.write(frame);
  } catch (err) {
    console.error('[WebSocket] Error sending frame to client:', err.message);
  }
}

/**
 * Attach WebSocket upgrade handling to a Node.js http.Server instance.
 *
 * @param {import('http').Server} server
 */
function attachWebSocketServer(server) {
  server.on('upgrade', (req, socket, head) => {
    // Only handle WebSocket requests intended for /ws or root /ws path
    const parsedUrl = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
    if (!parsedUrl.pathname.startsWith('/ws') && parsedUrl.pathname !== '/socket') {
      // Not a WebVitals WebSocket endpoint — respond 404 or let other handlers manage
      socket.write('HTTP/1.1 404 Not Found\r\n\r\n');
      socket.destroy();
      return;
    }

    const validation = validateUpgradeRequest(req);
    if (!validation.valid) {
      socket.write(`HTTP/1.1 400 Bad Request\r\n\r\n${validation.reason || 'Bad Request'}`);
      socket.destroy();
      return;
    }

    // Complete the RFC 6455 handshake
    writeHandshakeResponse(socket, validation.key);

    // Initial query scanId if supplied: /ws?scanId=1234-5678
    const initialScanId = parsedUrl.searchParams.get('scanId');

    // Create client session wrapper
    const client = {
      socket,
      scanId: null,
      unsubscribeProgress: null,
      isAlive: true,
      buffer: head && head.length > 0 ? Buffer.from(head) : Buffer.alloc(0),
    };

    _clients.add(client);
    console.log(`[WebSocket] Client connected. Total active clients: ${_clients.size}`);

    // Subscribe helper
    const subscribeToScan = (targetScanId) => {
      if (!targetScanId || typeof targetScanId !== 'string') return;

      // Clean up previous subscription if any
      if (client.unsubscribeProgress) {
        client.unsubscribeProgress();
        client.unsubscribeProgress = null;
      }

      client.scanId = targetScanId;

      // 1. Immediately send current snapshot if available
      const inFlight = getPublicState(targetScanId);
      if (inFlight) {
        sendJson(client.socket, buildEvent('SCAN_SNAPSHOT', inFlight, {
          stages: inFlight.stages,
          report: inFlight.report,
        }));
      } else {
        // Check historical/persisted scans
        const persisted = scanRepository.getScan(targetScanId);
        if (persisted) {
          sendJson(client.socket, {
            type: 'SCAN_SNAPSHOT',
            scanId: targetScanId,
            status: 'COMPLETE',
            progress: 100,
            message: 'Scan complete',
            timestamp: persisted.timestamp || new Date().toISOString(),
            report: persisted,
          });
        } else {
          sendJson(client.socket, {
            type: 'SCAN_NOT_FOUND',
            scanId: targetScanId,
            message: `No active or historical scan found for ID: ${targetScanId}`,
          });
        }
      }

      // 2. Subscribe to live progress emitter
      client.unsubscribeProgress = subscribeProgress(targetScanId, (event) => {
        sendJson(client.socket, event);
      });
    };

    if (initialScanId) {
      subscribeToScan(initialScanId);
    }

    // Handle incoming data & decode frames
    socket.on('data', (chunk) => {
      client.isAlive = true;
      client.buffer = Buffer.concat([client.buffer, chunk]);

      try {
        const { frames, remainder } = parseFrames(client.buffer);
        client.buffer = remainder;

        for (const frame of frames) {
          if (frame.opcode === OPCODES.PING) {
            // Heartbeat ping -> send pong frame
            if (socket.writable) socket.write(encodeTextFrame(JSON.stringify({ type: 'PONG' })));
          } else if (frame.opcode === OPCODES.PONG) {
            client.isAlive = true;
          } else if (frame.opcode === OPCODES.CLOSE) {
            // Echo close frame & clean up
            if (socket.writable) socket.write(encodeCloseFrame(1000, 'Normal Closure'));
            socket.end();
          } else if (frame.opcode === OPCODES.TEXT) {
            const text = frame.payload.toString('utf8');
            try {
              const msg = JSON.parse(text);
              if (msg.type === 'SUBSCRIBE' && msg.scanId) {
                subscribeToScan(msg.scanId);
              } else if (msg.type === 'UNSUBSCRIBE') {
                if (client.unsubscribeProgress) {
                  client.unsubscribeProgress();
                  client.unsubscribeProgress = null;
                }
                client.scanId = null;
              } else if (msg.type === 'PING') {
                sendJson(client.socket, { type: 'PONG', timestamp: new Date().toISOString() });
              }
            } catch (jsonErr) {
              console.warn('[WebSocket] Invalid JSON received from client:', text.slice(0, 100));
            }
          }
        }
      } catch (parseErr) {
        console.error('[WebSocket] Frame parsing error:', parseErr.message);
        if (socket.writable) {
          socket.write(encodeCloseFrame(1002, 'Protocol Error'));
        }
        socket.destroy();
      }
    });

    const cleanupClient = () => {
      if (client.unsubscribeProgress) {
        client.unsubscribeProgress();
        client.unsubscribeProgress = null;
      }
      _clients.delete(client);
      console.log(`[WebSocket] Client disconnected. Total active clients: ${_clients.size}`);
    };

    socket.on('close', cleanupClient);
    socket.on('end', cleanupClient);
    socket.on('error', (err) => {
      console.warn('[WebSocket] Socket error:', err.message);
      cleanupClient();
      socket.destroy();
    });
  });

  // Setup periodic heartbeat to drop unacknowledged or dead connections
  const interval = setInterval(() => {
    for (const client of _clients) {
      if (!client.isAlive) {
        console.log('[WebSocket] Terminating inactive/dead connection');
        if (client.unsubscribeProgress) client.unsubscribeProgress();
        client.socket.destroy();
        _clients.delete(client);
      } else {
        client.isAlive = false;
        if (client.socket.writable) {
          try {
            client.socket.write(encodePingFrame());
          } catch {
            client.socket.destroy();
            _clients.delete(client);
          }
        }
      }
    }
  }, HEARTBEAT_INTERVAL_MS);

  if (interval.unref) interval.unref();

  return server;
}

/**
 * Returns diagnostic statistics about active WebSocket connections.
 */
function getWebSocketStats() {
  const scanSubscribers = {};
  for (const client of _clients) {
    if (client.scanId) {
      scanSubscribers[client.scanId] = (scanSubscribers[client.scanId] || 0) + 1;
    }
  }

  return {
    totalClients: _clients.size,
    scanSubscribers,
  };
}

module.exports = {
  attachWebSocketServer,
  getWebSocketStats,
  sendJson,
};
