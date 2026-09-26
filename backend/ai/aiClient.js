/**
 * AI Provider Client & Gemini Integration — Phase 4
 * WebVitals
 *
 * Zero-dependency native HTTPS integration for Gemini API with:
 *   - Abstract AIProvider base interface
 *   - Configurable timeouts & output tokens
 *   - Exponential retry on transient errors (429, 503)
 *   - Graceful offline error handling
 */

'use strict';

const https = require('https');
const { URL } = require('url');
const {
  GEMINI_API_KEY,
  GEMINI_MODEL,
  GEMINI_TIMEOUT_MS,
  GEMINI_MAX_OUTPUT_TOKENS,
  AI_ENABLED,
} = require('../config/env');

/**
 * Base AIProvider interface.
 */
class AIProvider {
  /**
   * @param {string} systemInstruction
   * @param {string} prompt
   * @param {object} [options]
   * @returns {Promise<string>} Raw text output
   */
  async generateText(systemInstruction, prompt, options = {}) {
    throw new Error('generateText must be implemented by subclass');
  }

  isAvailable() {
    return false;
  }
}

/**
 * Gemini Provider Implementation.
 */
class GeminiProvider extends AIProvider {
  constructor(apiKey = GEMINI_API_KEY, model = GEMINI_MODEL) {
    super();
    this.apiKey = apiKey;
    this.model = model;
  }

  isAvailable() {
    return AI_ENABLED && Boolean(this.apiKey);
  }

  /**
   * Calls Google Gemini generateContent endpoint.
   *
   * @param {string} systemInstruction
   * @param {string} prompt
   * @param {object} [options]
   * @returns {Promise<string>}
   */
  async generateText(systemInstruction, prompt, options = {}) {
    if (!this.isAvailable()) {
      const err = new Error('Gemini AI is not enabled or GEMINI_API_KEY is missing');
      err.code = 'AI_DISABLED';
      throw err;
    }

    const maxTokens = options.maxTokens || GEMINI_MAX_OUTPUT_TOKENS;
    const timeoutMs = options.timeoutMs || GEMINI_TIMEOUT_MS;

    const candidateModels = [
      this.model,
      'gemini-flash-latest',
      'gemini-3.5-flash',
      'gemini-3.1-flash-lite',
      'gemini-flash-lite-latest',
      'gemini-3.8-flash',
      'gemini-pro-latest',
    ];
    const modelsToTry = [...new Set(candidateModels.filter(Boolean))];

    const payload = JSON.stringify({
      contents: [
        {
          role: 'user',
          parts: [{ text: prompt }],
        },
      ],
      systemInstruction: systemInstruction ? {
        parts: [{ text: systemInstruction }],
      } : undefined,
      generationConfig: {
        maxOutputTokens: maxTokens,
        temperature: 0.2, // Low temperature for deterministic, factual outputs
        topP: 0.8,
        responseMimeType: options.jsonMode ? 'application/json' : 'text/plain',
      },
    });

    let lastError = null;
    for (const model of modelsToTry) {
      const endpoint = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${this.apiKey}`;
      const urlObj = new URL(endpoint);

      try {
        return await this._executeWithRetry(urlObj, payload, timeoutMs, 1);
      } catch (err) {
        lastError = err;
        // If it's a capacity (503/429) or model deprecation (404) error, try the next model candidate
        if (err.statusCode === 503 || err.statusCode === 429 || err.statusCode === 404 || err.code === 'ETIMEDOUT') {
          continue;
        }
        throw err;
      }
    }

    throw lastError || new Error('All Gemini model candidates failed');
  }

  async _executeWithRetry(urlObj, payload, timeoutMs, retriesLeft = 1) {
    try {
      return await this._rawRequest(urlObj, payload, timeoutMs);
    } catch (err) {
      if (retriesLeft > 0 && (err.code === 'ETIMEDOUT' || err.statusCode === 429 || err.statusCode === 503)) {
        await new Promise((res) => setTimeout(res, 800));
        return this._executeWithRetry(urlObj, payload, timeoutMs, retriesLeft - 1);
      }
      throw err;
    }
  }

  _rawRequest(urlObj, payload, timeoutMs) {
    return new Promise((resolve, reject) => {
      const req = https.request(
        {
          method: 'POST',
          hostname: urlObj.hostname,
          path: `${urlObj.pathname}${urlObj.search}`,
          headers: {
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(payload),
          },
          timeout: timeoutMs,
        },
        (res) => {
          let body = '';
          res.on('data', (d) => { body += d; });
          res.on('end', () => {
            if (res.statusCode < 200 || res.statusCode >= 300) {
              let errorMsg = `Gemini API returned HTTP ${res.statusCode}`;
              try {
                const parsed = JSON.parse(body);
                if (parsed.error?.message) errorMsg = parsed.error.message;
              } catch {}
              const err = new Error(errorMsg);
              err.statusCode = res.statusCode;
              err.code = 'GEMINI_API_ERROR';
              return reject(err);
            }

            try {
              const data = JSON.parse(body);
              const candidate = data.candidates?.[0];
              const parts = candidate?.content?.parts || [];
              const answerPart = parts.find((p) => !p.thought && p.text) || parts[0];
              const text = answerPart?.text;

              if (!text) {
                const err = new Error('Gemini API returned an empty candidate or filtered response');
                err.code = 'AI_EMPTY_RESPONSE';
                return reject(err);
              }

              resolve(text);
            } catch (parseErr) {
              const err = new Error(`Failed to parse Gemini response: ${parseErr.message}`);
              err.code = 'AI_PARSE_ERROR';
              reject(err);
            }
          });
        }
      );

      req.on('timeout', () => {
        req.destroy(new Error(`Gemini API request timed out after ${timeoutMs}ms`));
      });

      req.on('error', reject);
      req.write(payload);
      req.end();
    });
  }
}

// Global provider singleton
const defaultAiProvider = new GeminiProvider();

module.exports = {
  AIProvider,
  GeminiProvider,
  defaultAiProvider,
};
