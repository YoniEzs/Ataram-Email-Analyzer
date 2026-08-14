/**
 * Configuration
 */

const CONFIG = {
    // API endpoint - change this to your backend URL
    // Anywhere but a local dev box the API is same-origin: nginx reverse-proxies
    // /api and /health to the Flask backend, so no CORS and no hardcoded host.
    API_BASE_URL: window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1'
        ? 'http://localhost:5000'
        : '',

    // Endpoints
    ENDPOINTS: {
        ANALYZE: '/api/analyze',
        HEALTH: '/health'
    },

    // File upload limits. Must match MAX_UPLOAD_MB on the server and
    // client_max_body_size in nginx: advertising more than the server accepts
    // sends the user through a long upload only to be rejected at the end.
    MAX_FILE_SIZE: 25 * 1024 * 1024, // 25MB
    ALLOWED_EXTENSIONS: ['eml', 'msg'],

    // UI
    ANIMATION_DURATION: 300
};

// Export for use in other files
window.CONFIG = CONFIG;
