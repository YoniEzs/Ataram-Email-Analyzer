/**
 * Apply the saved theme before first paint to avoid a flash.
 *
 * Loaded as a blocking external script in <head>, before the stylesheets, so
 * it still runs pre-paint. It lives in a file rather than inline because the
 * desktop build serves this page through Flask, whose CSP is script-src
 * 'self' — inline scripts are refused there by design.
 */
(function () {
    try {
        var t = localStorage.getItem('emailAnalyzer_theme');
        if (t === 'light' || t === 'dark') {
            document.documentElement.setAttribute('data-theme', t);
        }
    } catch (e) { /* localStorage unavailable */ }
})();
