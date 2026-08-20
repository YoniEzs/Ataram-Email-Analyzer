/**
 * Lightweight i18n layer.
 *
 * English strings double as translation keys: t('Analyze Email') returns the
 * Hebrew translation when the UI language is 'he', otherwise the key itself.
 * Static HTML is translated via data-i18n / data-i18n-placeholder attributes.
 */

const I18N_TRANSLATIONS = {
    he: {
        // Artifacts card
        'Display Name': 'שם תצוגה',
        'Sender Domain': 'דומיין השולח',
        'Subject Charsets': 'מערכות תווים בנושא',
        'To': 'אל',
        'Cc': 'עותק',
        'Delivered via BCC': 'נמסר בעותק מוסתר',
        'Date (UTC)': 'תאריך (UTC)',
        'Skew vs First Hop': 'הפרש מול התחנה הראשונה',
        'HELO Claimed': 'HELO שהוצהר',
        // Enrichment status vocabulary
        'reverse_dns': 'DNS הפוך',
        'ip_intel': 'מודיעין IP',
        'spf_advisory': 'SPF מייעץ',
        'mx': 'רשומות MX',
        'ok': 'תקין',
        'disabled': 'מושבת',
        'unavailable': 'לא זמין',
        'error': 'שגיאה',
        'skipped_no_public_ip': 'דולג - אין IP ציבורי',
        'pending': 'ממתין',
        'Artifacts': 'ארטיפקטים',
        'Forward-Confirmed rDNS': 'אימות DNS הפוך דו-כיווני',
        'HELO vs Reverse DNS': 'HELO מול DNS הפוך',
        'ASN': 'מספר מערכת אוטונומית',
        'BGP Prefix': 'קידומת BGP',
        'Allocated To': 'הוקצה ל',
        'Network': 'רשת',
        'Abuse Contact': 'איש קשר לדיווח שימוש לרעה',
        'Advisory SPF': 'בדיקת SPF מייעצת',
        'Advisory only - never trusted': 'מייעץ בלבד - לעולם לא נחשב אמין',
        'Observed': 'נצפה',
        'Computed': 'מחושב',
        'Header claim': 'טענה מהכותרות',
        'Observed = checked live at analysis time. Header claim = read from the file and forgeable.':
            'נצפה = נבדק בזמן אמת בעת הניתוח. טענה מהכותרות = נקרא מהקובץ וניתן לזיוף.',
        'Mismatch': 'אי-התאמה',
        'No enrichment data available': 'אין נתוני העשרה זמינים',
        'Lookup disabled': 'הבדיקה מושבתת',
        'No public sending IP': 'לא נמצאה כתובת IP ציבורית',
        'No data returned': 'לא הוחזרו נתונים',
        'Lookup failed': 'הבדיקה נכשלה',
        'Lookup timed out': 'הבדיקה חרגה מהזמן',
        'in Cc': 'בעותק',
        'via BCC': 'בעותק מוסתר',
        'undisclosed': 'לא נחשפו',
        'Copy Artifacts': 'העתקת ארטיפקטים',
        'Copy the artifact block below': 'העתיקו את בלוק הארטיפקטים שלהלן',
        'Field': 'שדה',
        'Value': 'ערך',
        'Flags': 'סימונים',
        'Header claims (forgeable, read from the uploaded file)':
            'טענות מהכותרות (ניתנות לזיוף, נקראו מהקובץ שהועלה)',
        'Observed (checked live at analysis time)': 'נצפה (נבדק בזמן אמת בעת הניתוח)',
        // SPF / FCrDNS result vocabulary
        'pass': 'עבר',
        'fail': 'נכשל',
        'softfail': 'כשל רך',
        'neutral': 'ניטרלי',
        'none': 'אין',
        'permerror': 'שגיאה קבועה',
        'temperror': 'שגיאה זמנית',
        'no_ptr': 'אין רשומת PTR',
        'lookup_failed': 'הבדיקה נכשלה',
        // Artifact flag labels
        'fcrdns_fail': 'אימות DNS הפוך נכשל',
        'no_ptr_record': 'אין רשומת PTR',
        'ptr_helo_mismatch': 'PTR אינו תואם ל-HELO',
        'no_public_sender_ip': 'לא נמצאה כתובת IP ציבורית של השולח',
        'sender_domain_has_no_mx': 'לדומיין השולח אין רשומות MX',
        'homoglyph_sender_domain': 'דומיין השולח מחקה דומיין לטיני',
        'punycode_sender_domain': 'דומיין השולח מקודד ב-punycode',
        'display_name_domain_mismatch': 'שם התצוגה מכיל כתובת מדומיין אחר',
        'disposable_sender_domain': 'דומיין השולח הוא שירות דואר זמני',
        'freemail_sender': 'השולח משתמש בדואר צרכני',
        'multiple_from_addresses': 'קיימות מספר כתובות From',
        'no_from_header': 'חסרה כותרת From',
        'bidi_override_in_subject': 'תווי היפוך כיווניות בנושא',
        'zero_width_in_subject': 'תווים ברוחב אפס בנושא',
        'mixed_charsets_in_subject': 'ערבוב מערכות תווים בנושא',
        'reply_prefix_without_thread_headers': 'נושא של תגובה ללא כותרות שרשור',
        'empty_subject': 'נושא ריק',
        'possible_bcc_delivery': 'ייתכן שנשלח בעותק מוסתר',
        'undisclosed_recipients': 'הנמענים לא נחשפו',
        'no_visible_recipients': 'אין נמענים גלויים',
        'large_recipient_list': 'רשימת נמענים גדולה במיוחד',
        'reply_to_differs_from_sender': 'כתובת המענה שונה מהשולח',
        'return_path_differs_from_sender': 'נתיב החזרה שונה מהשולח',
        'freemail_reply_target': 'המענה מופנה לדואר צרכני',
        'freemail_return_path': 'נתיב החזרה מופנה לדואר צרכני',
        'future_dated': 'התאריך בעתיד',
        'implausibly_old': 'התאריך ישן באופן חריג',
        'unparseable_date': 'לא ניתן לפענח את התאריך',
        'missing_date': 'חסר תאריך',
        'missing_timezone': 'חסר אזור זמן',
        'date_before_first_hop': 'התאריך מוקדם מהתחנה הראשונה',
        'date_after_last_hop': 'התאריך מאוחר מהתחנה האחרונה',
        'received_chain_out_of_order': 'שרשרת התחנות אינה מסודרת',
        'homoglyph_domain': 'הדומיין מחקה דומיין לטיני',
        'disposable_domain': 'דומיין דואר זמני',
        'message_id_domain_differs_from_sender': 'דומיין Message-ID שונה מהשולח',
        'missing_message_id': 'חסר Message-ID',
        'x_originating_ip_disagrees_with_chain': 'X-Originating-IP סותר את שרשרת התחנות',
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

        // Upload / layout
        'Advanced options': 'אפשרויות מתקדמות',
        'Analyze another email': 'ניתוח מייל נוסף',
        'Switch to dark theme': 'מעבר למצב כהה',
        'Switch to light theme': 'מעבר למצב בהיר',

        // Results — summary + score breakdown
        'Why this score': 'מדוע הציון הזה',
        'No scoring factors — no strong signals detected': 'אין גורמי ניקוד — לא זוהו סימנים חזקים',
        'Findings': 'ממצאים',
        'Hops': 'תחנות',
        'Overview': 'סקירה',
        'Details': 'פרטים',
        'pts': 'נק׳',

        // Results — tabs
        'Sender & IP': 'שולח ו-IP',
        'Routing': 'ניתוב',
        'Headers': 'כותרות',
        'Nothing to show here': 'אין מה להציג כאן',

        // Pivot actions
        'Copy': 'העתקה',
        'Copy all URLs': 'העתקת כל הקישורים',
        'Copy all hashes': 'העתקת כל ההאשים',
        'Shown defanged so nobody clicks one by accident. Copy gives the real URL.':
            'הקישורים מוצגים מנוטרלים כדי שאיש לא ילחץ בטעות. כפתור ההעתקה מעתיק את הכתובת האמיתית.',
        'URLs above are defanged - restore hxxp to http before use.':
            'הקישורים שלמעלה מנוטרלים - יש להחזיר hxxp ל-http לפני שימוש.',
        'Copied': 'הועתק',
        'Look up': 'בדיקה',
        'Search': 'חיפוש',
        'Reverse DNS': 'DNS הפוך',

        // Results — conclusion (official artifacts)
        'Conclusion': 'סיכום',
        'Official artifacts extracted from this email': 'ממצאים רשמיים שחולצו מהמייל',
        'Sender Address': 'כתובת השולח',
        'Subject Line': 'שורת הנושא',
        'Recipients': 'נמענים',
        'Date + Time': 'תאריך ושעה',
        'Sending Server IP': 'כתובת ה-IP של שרת השליחה',
        'Reverse DNS of Sending Server': 'DNS הפוך של שרת השליחה',
        'Reply-To Address': 'כתובת השב־אל',

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
    if (window.uiController && typeof window.uiController._applyThemeLabel === 'function') {
        window.uiController._applyThemeLabel();
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
