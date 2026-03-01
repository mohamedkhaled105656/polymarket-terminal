/**
 * proxy-patch.cjs
 *
 * Strategy: Patch https.request at the lowest level with domain filtering.
 * This affects ALL HTTPS requests, but we only route Polymarket domains through proxy.
 *
 * RPC Polygon calls are NOT affected because:
 * - They go to polygon-rpc.com (not in whitelist)
 * - They use ethers.js JsonRpcProvider which uses fetch or its own transport
 */

const PROXY_URL = process.env.PROXY_URL || '';

if (PROXY_URL) {
    const https = require('https');
    const http = require('http');
    const { URL } = require('url');
    const net = require('net');
    const tls = require('tls');

    const proxyUrl = new URL(PROXY_URL);
    const proxyHost = proxyUrl.hostname;
    const proxyPort = parseInt(proxyUrl.port) || (proxyUrl.protocol === 'https:' ? 443 : 80);
    const proxyAuth = (proxyUrl.username || proxyUrl.password)
        ? Buffer.from(`${proxyUrl.username}:${proxyUrl.password}`).toString('base64')
        : null;

    // Polymarket domains ONLY
    const POLY_HOSTS = new Set([
        'polymarket.com',
        'www.polymarket.com',
        'clob.polymarket.com',
        'gamma-api.polymarket.com',
        'data-api.polymarket.com',
    ]);

    function shouldProxy(hostname) {
        // Check exact match or subdomain
        if (POLY_HOSTS.has(hostname)) return true;
        for (const host of POLY_HOSTS) {
            if (hostname.endsWith('.' + host)) return true;
        }
        return false;
    }

    // Store original request
    const originalHttpsRequest = https.request;
    const originalHttpRequest = http.request;

    // Create proxy-aware https.request
    https.request = function(options, callback) {
        let hostname;

        if (typeof options === 'string') {
            try {
                hostname = new URL(options).hostname;
            } catch {
                return originalHttpsRequest.apply(https, arguments);
            }
        } else if (options.hostname || options.host) {
            hostname = options.hostname || (typeof options.host === 'string' ? options.host.split(':')[0] : options.host);
        }

        // If not Polymarket, use direct connection
        if (!hostname || !shouldProxy(hostname)) {
            return originalHttpsRequest.apply(https, arguments);
        }

        // For Polymarket: create CONNECT tunnel through proxy
        const targetHost = hostname;
        const targetPort = 443;

        // Build CONNECT request headers
        const connectHeaders = {
            'Host': `${targetHost}:${targetPort}`,
        };
        if (proxyAuth) {
            connectHeaders['Proxy-Authorization'] = `Basic ${proxyAuth}`;
        }

        // Create socket connection through proxy
        const connectOptions = {
            host: proxyHost,
            port: proxyPort,
            method: 'CONNECT',
            path: `${targetHost}:${targetPort}`,
            headers: connectHeaders,
        };

        // Make CONNECT request to proxy
        const connectReq = originalHttpRequest(connectOptions);

        // Return a promise-like request that waits for tunnel
        const deferredReq = {
            on: function(event, handler) {
                if (event === 'response' || event === 'error' || event === 'timeout') {
                    this._deferredHandlers = this._deferredHandlers || {};
                    this._deferredHandlers[event] = handler;
                }
                return this;
            },
            once: function(event, handler) {
                return this.on(event, handler);
            },
            write: function(chunk) {
                if (this._realRequest) {
                    this._realRequest.write(chunk);
                } else {
                    this._buffer = this._buffer || [];
                    this._buffer.push(chunk);
                }
                return true;
            },
            end: function(chunk) {
                if (chunk) this.write(chunk);
                if (this._realRequest) {
                    this._realRequest.end();
                } else {
                    this._ended = true;
                }
                return this;
            },
            setTimeout: function(ms) {
                this._timeout = ms;
                if (this._realRequest) {
                    this._realRequest.setTimeout(ms);
                }
                return this;
            },
            setHeader: function(name, value) {
                this._headers = this._headers || {};
                this._headers[name] = value;
                return this;
            },
            abort: function() {
                if (this._realRequest) {
                    this._realRequest.abort();
                }
                if (this._connectReq) {
                    this._connectReq.abort();
                }
            }
        };

        connectReq.on('connect', (res, socket) => {
            if (res.statusCode !== 200) {
                const err = new Error(`Proxy CONNECT failed: ${res.statusCode}`);
                if (deferredReq._deferredHandlers && deferredReq._deferredHandlers.error) {
                    deferredReq._deferredHandlers.error(err);
                }
                return;
            }

            // Wrap socket in TLS
            const tlsOptions = {
                socket: socket,
                servername: targetHost,
                rejectUnauthorized: options.rejectUnauthorized !== false,
            };
            const tlsSocket = tls.connect(tlsOptions);

            // Now make actual HTTPS request through tunnel
            const requestOptions = typeof options === 'string'
                ? { ...new URL(options), createConnection: () => tlsSocket }
                : { ...options, createConnection: () => tlsSocket };

            const realReq = originalHttpsRequest(requestOptions, (res) => {
                if (callback) callback(res);
                if (deferredReq._deferredHandlers && deferredReq._deferredHandlers.response) {
                    deferredReq._deferredHandlers.response(res);
                }
            });

            // Apply deferred operations
            if (deferredReq._headers) {
                for (const [name, value] of Object.entries(deferredReq._headers)) {
                    realReq.setHeader(name, value);
                }
            }
            if (deferredReq._timeout) {
                realReq.setTimeout(deferredReq._timeout);
            }
            if (deferredReq._buffer) {
                for (const chunk of deferredReq._buffer) {
                    realReq.write(chunk);
                }
            }
            if (deferredReq._ended) {
                realReq.end();
            }

            // Forward events
            realReq.on('error', (err) => {
                if (deferredReq._deferredHandlers && deferredReq._deferredHandlers.error) {
                    deferredReq._deferredHandlers.error(err);
                }
            });
            realReq.on('timeout', () => {
                if (deferredReq._deferredHandlers && deferredReq._deferredHandlers.timeout) {
                    deferredReq._deferredHandlers.timeout();
                }
            });

            deferredReq._realRequest = realReq;
            deferredReq._connectReq = connectReq;
        });

        connectReq.on('error', (err) => {
            if (deferredReq._deferredHandlers && deferredReq._deferredHandlers.error) {
                deferredReq._deferredHandlers.error(err);
            }
        });

        connectReq.end();

        return deferredReq;
    };

    // Also patch http.request for completeness (though CLOB uses HTTPS)
    http.request = function(options, callback) {
        let hostname;

        if (typeof options === 'string') {
            try {
                hostname = new URL(options).hostname;
            } catch {
                return originalHttpRequest.apply(http, arguments);
            }
        } else if (options.hostname || options.host) {
            hostname = options.hostname || (typeof options.host === 'string' ? options.host.split(':')[0] : options.host);
        }

        // Only proxy Polymarket domains
        if (!hostname || !shouldProxy(hostname)) {
            return originalHttpRequest.apply(http, arguments);
        }

        // For HTTP, route through proxy directly
        const targetUrl = typeof options === 'string' ? new URL(options) : null;
        const path = targetUrl ? targetUrl.pathname + targetUrl.search : (options.path || '/');

        const proxyOptions = {
            host: proxyHost,
            port: proxyPort,
            method: options.method || 'GET',
            path: path,
            headers: { ...(options.headers || {}) },
        };

        if (proxyAuth) {
            proxyOptions.headers['Proxy-Authorization'] = `Basic ${proxyAuth}`;
        }

        return originalHttpRequest.call(http, proxyOptions, callback);
    };

    console.log(`[proxy-patch] HTTPS/HTTP CONNECT tunnel active for Polymarket only`);
    console.log(`[proxy-patch] RPC Polygon and other domains use direct connection`);
} else {
    console.log('[proxy-patch] No PROXY_URL set, skipping patch');
}
