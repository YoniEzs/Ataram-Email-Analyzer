/**
 * Configuration
 */

const CONFIG = {
    // API endpoint - change this to your backend URL
    API_BASE_URL: window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1'
        ? 'http://localhost:5000'
        : 'https://ataram-email-analyzer.onrender.com',  // Your Render backend URL

    // Endpoints
    ENDPOINTS: {
        ANALYZE: '/api/analyze',
        HEALTH: '/health'
    },

    // File upload limits
    MAX_FILE_SIZE: 50 * 1024 * 1024, // 50MB
    ALLOWED_EXTENSIONS: ['eml', 'msg'],

    // UI
    ANIMATION_DURATION: 300
};

// Export for use in other files
window.CONFIG = CONFIG;
