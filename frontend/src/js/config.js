/**
 * Runtime configuration.
 *
 * The safe default is same-origin. Self-hosted nginx proxies /api and /health
 * to the backend. Static-host deployments must set API_BASE_URL explicitly in
 * runtime-config.js; no upload is ever sent to the project owner's server by
 * default.
 */

const RUNTIME_CONFIG = Object.freeze(window.ATARAM_CONFIG || {});

function normalizeApiBaseUrl(value) {
    if (!value) return '';
    try {
        const url = new URL(value, window.location.origin);
        const isLocal = ['localhost', '127.0.0.1', '::1'].includes(url.hostname);
        if (url.protocol !== 'https:' && !isLocal) {
            throw new Error('Remote API_BASE_URL must use HTTPS');
        }
        return url.href.replace(/\/$/, '');
    } catch (error) {
        console.error('Invalid ATARAM_CONFIG.API_BASE_URL:', error.message);
        return '';
    }
}

const CONFIG = {
    API_BASE_URL: normalizeApiBaseUrl(RUNTIME_CONFIG.API_BASE_URL),

    ENDPOINTS: {
        ANALYZE: '/api/v1/analyze',
        HEALTH: '/health'
    },

    MAX_FILE_SIZE: 25 * 1024 * 1024,
    ALLOWED_EXTENSIONS: ['eml', 'msg'],

    REQUEST_TIMEOUT_MS: 120000,
    HEALTH_TIMEOUT_MS: 10000,
    ANIMATION_DURATION: 300
};

window.CONFIG = CONFIG;
