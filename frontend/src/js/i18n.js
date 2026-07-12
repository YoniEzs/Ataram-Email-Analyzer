/**
 * Lightweight i18n layer.
 *
 * English strings double as translation keys: t('Analyze Email') returns the
 * Hebrew translation when the UI language is 'he', otherwise the key itself.
 * Static HTML is translated via data-i18n / data-i18n-placeholder attributes.
 */

const I18N_TRANSLATIONS = {
    he: {
        // Header / general
        'Advanced Email Security Analysis': 'ניתוח אבטחת דוא"ל מתקדם',
        'Analyze Email': 'ניתוח מייל',
        'Upload .eml or .msg file for comprehensive security analysis': 'העלו קובץ ‎.eml או ‎.msg לניתוח אבטחה מקיף',
        'Drag and drop your email file here': 'גררו את קובץ המייל לכאן',
        'or': 'או',
        'Choose File': 'בחירת קובץ',
        'Supports .eml and .msg files (max 25MB)': 'נתמכים קבצי ‎.eml ו-‎.msg (עד 25MB)',
        'AbuseIPDB API Key (optional)': 'מפתח API של AbuseIPDB (אופציונלי)',
        'Enter your AbuseIPDB API key for IP reputation checks': 'הזינו מפתח AbuseIPDB לבדיקות מוניטין IP',
        'Get your free API key at': 'מפתח חינמי זמין בכתובת',
        'The API key is sent to the configured analysis server and then to AbuseIPDB. It is cleared from this field after each request.': 'המפתח נשלח לשרת הניתוח המוגדר ומשם ל-AbuseIPDB. השדה נמחק לאחר כל בקשה.',
        'Analysis server': 'שרת הניתוח',
        'Analyzing email...': 'מנתח את המייל...',

        // Progress steps
        'Parsing email...': 'מפענח את המייל...',
        'Checking DNS records...': 'בודק רשומות DNS...',
        'Looking up domain info...': 'מאתר מידע על הדומיין...',
        'Checking IP reputation...': 'בודק מוניטין IP...',
        'Analyzing content & URLs...': 'מנתח תוכן וקישורים...',
        'Calculating risk score...': 'מחשב ציון סיכון...',
        'Uploading...': 'מעלה...',

        // History
        'Recent Analyses': 'ניתוחים אחרונים',
        'Clear': 'ניקוי',
        "History is saved only in this browser's local storage and includes filename, risk score, and verdict summary. Use Clear to remove it.": 'ההיסטוריה נשמרת רק בדפדפן זה (localStorage) וכוללת שם קובץ, ציון סיכון ותמצית. לחצו "ניקוי" למחיקה.',
        'No previous analyses.': 'אין ניתוחים קודמים.',

        // Export / error
        'Download Report (JSON)': 'הורדת דוח (JSON)',
        'Print Report': 'הדפסת דוח',
        'Analysis Failed': 'הניתוח נכשל',
        'Try Again': 'ניסיון חוזר',
        'The analysis timed out. Please try again.': 'זמן הניתוח פג. נסו שוב.',
        'Too many requests. Please wait a minute and try again.': 'יותר מדי בקשות. המתינו דקה ונסו שוב.',
        'Network error. Check that the analysis server is reachable.': 'שגיאת רשת. ודאו שהשרת זמין.',
        'No file selected': 'לא נבחר קובץ',
        'Failed to analyze email. Please try again.': 'ניתוח המייל נכשל. נסו שוב.',

        // Features section
        'What We Analyze': 'מה אנחנו בודקים',
        'Authentication': 'אימות',
        'DKIM verification and untrusted SPF/DMARC header claims': 'אימות DKIM והצגת טענות SPF/DMARC לא־מהימנות מהכותרות',
        'URLs & Links': 'קישורים',
        'Suspicious URL detection and analysis': 'זיהוי וניתוח קישורים חשודים',
        'Attachments': 'קבצים מצורפים',
        'Malicious file type identification': 'זיהוי קבצים זדוניים',
        'Content Analysis': 'ניתוח תוכן',
        'Phishing keyword and pattern detection': 'זיהוי ביטויי ודפוסי פישינג',
        'IP Reputation': 'מוניטין IP',
        'Sender IP abuse database lookup': 'בדיקת כתובת השולח במאגרי Abuse',
        'Risk Score': 'ציון סיכון',
        'Comprehensive threat assessment': 'הערכת איום מקיפה',
        'Email is processed by the configured analysis server. See PRIVACY.md before uploading sensitive material.': 'המייל מעובד בשרת הניתוח המוגדר. קראו את PRIVACY.md לפני העלאת חומר רגיש.',

        // Results — cards and rows
        'Email Headers': 'כותרות המייל',
        'From': 'מאת',
        'To / Cc': 'אל / עותק',
        'Subject': 'נושא',
        'Date': 'תאריך',
        'Reply-To': 'השב אל',
        'Return-Path': 'נתיב חזרה',
        'Message-ID': 'מזהה הודעה',
        'Results': 'תוצאות',
        'SPF Record': 'רשומת SPF',
        'DMARC Record': 'רשומת DMARC',
        'DKIM Record': 'רשומת DKIM',
        'Sender Information': 'פרטי השולח',
        'Domain': 'דומיין',
        'Sender IP': 'כתובת IP של השולח',
        'WHOIS': 'רישום דומיין (WHOIS)',
        'Urgent Phrases': 'ביטויי דחיפות',
        'Generic Greetings': 'פניות גנריות',
        'Credential Requests': 'בקשות פרטים רגישים',
        'HTML Forms': 'טפסי HTML',
        'Scripts': 'סקריפטים',
        'Hidden Elements': 'רכיבים מוסתרים',
        'YARA Matches': 'התאמות YARA',
        'URLs': 'קישורים',
        'Email Routing': 'נתיב המייל',
        'Header Forensics': 'פורנזיקת כותרות',
        'Hop Count': 'מספר תחנות',
        'Originating IP': 'כתובת מקור',
        'Sender Timezone': 'אזור זמן השולח',
        'Public IPs in Route': 'כתובות ציבוריות בנתיב',
        'Suspicious Indicators': 'סימנים חשודים',
        'No URLs found in email': 'לא נמצאו קישורים במייל',
        'No attachments found': 'לא נמצאו קבצים מצורפים',
        'None': 'אין',
        'N/A': 'לא זמין',
        'Not found': 'לא נמצא',
        'Not available': 'לא זמין',
        'Not checked': 'לא נבדק',
        'Not detected': 'לא זוהה',
        'Unknown': 'לא ידוע',
        'Unknown type': 'סוג לא ידוע',
        'found': 'נמצאו',
        'suspicious': 'חשודים',
        'hops': 'תחנות',
        'Risk': 'סיכון',
        'Hop': 'תחנה',
        'Error': 'שגיאה',
        'Verified': 'אימות עצמאי',
        'Untrusted header claims': 'טענות כותרת לא־מהימנות',
        'Independent verification': 'אימות עצמאי',
        'DKIM alignment': 'יישור DKIM',
        'SPF and DMARC cannot be verified from an uploaded file alone': 'לא ניתן לאמת SPF ו-DMARC מקובץ שהועלה בלבד',

        // Risk levels + verdicts
        'low': 'נמוך',
        'medium': 'בינוני',
        'high': 'גבוה',
        'critical': 'קריטי',
        'HIGHLY SUSPICIOUS - Likely phishing or malicious': 'חשוד מאוד — ככל הנראה פישינג או תוכן זדוני',
        'SUSPICIOUS - Exercise extreme caution': 'חשוד — נדרשת זהירות יתרה',
        'QUESTIONABLE - Review carefully before interacting': 'מפוקפק — בדקו היטב לפני כל פעולה',
        'NO STRONG INDICATORS DETECTED - Not a guarantee of safety': 'לא זוהו סימנים חזקים — אין בכך הבטחה שהמייל בטוח',
    }
};

function i18nGetLang() {
    try {
        const saved = localStorage.getItem('emailAnalyzer_lang');
        if (saved === 'he' || saved === 'en') return saved;
    } catch (e) { /* localStorage unavailable */ }
    return (navigator.language || '').toLowerCase().startsWith('he') ? 'he' : 'en';
}

function t(key) {
    if (!key) return key;
    const lang = window.currentLang || 'en';
    const table = I18N_TRANSLATIONS[lang];
    return (table && table[key]) || key;
}

function setLanguage(lang) {
    window.currentLang = lang;
    try {
        localStorage.setItem('emailAnalyzer_lang', lang);
    } catch (e) { /* ignore */ }
    applyI18n();
}

function applyI18n() {
    const lang = window.currentLang || 'en';

    document.documentElement.lang = lang;
    document.documentElement.dir = lang === 'he' ? 'rtl' : 'ltr';

    document.querySelectorAll('[data-i18n]').forEach(el => {
        el.textContent = t(el.getAttribute('data-i18n'));
    });
    document.querySelectorAll('[data-i18n-placeholder]').forEach(el => {
        el.setAttribute('placeholder', t(el.getAttribute('data-i18n-placeholder')));
    });

    const toggle = document.getElementById('langToggle');
    if (toggle) {
        toggle.textContent = lang === 'he' ? 'English' : 'עברית';
    }

    // Re-render dynamic sections in the new language
    if (window.uiController && typeof window.uiController.renderHistory === 'function') {
        window.uiController.renderHistory();
    }
    if (window.resultsRenderer && window.lastAnalysisResult) {
        window.resultsRenderer.render(window.lastAnalysisResult);
    }
}

function initI18n() {
    window.currentLang = i18nGetLang();

    const toggle = document.getElementById('langToggle');
    if (toggle) {
        toggle.addEventListener('click', () => {
            setLanguage(window.currentLang === 'he' ? 'en' : 'he');
        });
    }

    applyI18n();
}

window.t = t;
window.initI18n = initI18n;
window.applyI18n = applyI18n;
