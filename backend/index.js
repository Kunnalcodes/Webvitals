/**
 * WebVitals Backend — Entry Point
 * Phase 1 — Security Hardened
 *
 * Zero-dependency Node.js server.
 */

'use strict';

const http = require('http');
const { PORT } = require('./config/env');
const { handleRequest } = require('./routes/router');
const { attachWebSocketServer } = require('./websocket/websocketServer');

function createServer() {
  const server = http.createServer((req, res) => {
    handleRequest(req, res).catch((err) => {
      console.error('[WebVitals] Unhandled request error:', err);
      if (!res.headersSent) {
        res.setHeader('Content-Type', 'application/json');
        res.writeHead(500);
        res.end(JSON.stringify({
          success: false,
          error: {
            code: 'INTERNAL_ERROR',
            message: 'An unexpected error occurred.',
            // Stack trace intentionally omitted from production response
          },
        }));
      }
    });
  });

  // Attach RFC 6455 WebSocket upgrade listener
  attachWebSocketServer(server);

  return server;
}

function startServer(port = PORT) {
  const server = createServer();
  return new Promise((resolve, reject) => {
    server.on('error', reject);
    server.listen(port, () => {
      console.log(`[WebVitals] Server listening on http://localhost:${port}`);
      console.log(`[WebVitals] WebSocket endpoint active at ws://localhost:${port}/ws`);
      console.log(`[WebVitals] Environment: ${process.env.NODE_ENV || 'development'}`);
      resolve(server);
    });
  });
}

if (require.main === module) {
  startServer().catch((err) => {
    console.error('[WebVitals] Failed to start server:', err);
    process.exit(1);
  });
}

module.exports = { createServer, startServer };

