(function () {
  'use strict';

  const RULES = [
    { cat: 'OpenAI-style API key', risk: 'high', re: /\bsk-[A-Za-z0-9]{20,}\b/g,
      explain: 'Looks like an API credential. Anyone who obtains it may be able to make authenticated or billed API calls.', placeholder: '[API_KEY_REDACTED]' },

    { cat: 'AWS access key ID', risk: 'high', re: /\bAKIA[0-9A-Z]{16}\b/g,
      explain: 'An AWS access key identifier can be paired with a secret key to access AWS resources.', placeholder: '[AWS_KEY_REDACTED]' },

    { cat: 'GitHub token', risk: 'high', re: /\bgh[pousr]_[A-Za-z0-9_\-]{20,}\b/g,
      explain: 'GitHub access tokens can grant access to repositories and other account resources.', placeholder: '[GITHUB_TOKEN_REDACTED]' },

    { cat: 'Slack token', risk: 'high', re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g,
      explain: 'Slack tokens can authenticate actions against a workspace as a user or app.', placeholder: '[SLACK_TOKEN_REDACTED]' },

    { cat: 'Private key block', risk: 'high', re: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g,
      explain: 'A private key is authentication or cryptographic material and should never be pasted into a public AI service.', placeholder: '[PRIVATE_KEY_BLOCK_REDACTED]' },

    { cat: 'JWT', risk: 'high', re: /\bey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g,
      explain: 'Looks like a JSON Web Token. It may contain identity or authorization claims.', placeholder: '[JWT_REDACTED]' },

    { cat: 'Database connection string', risk: 'high', re: /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis):\/\/[^\s"'<>]+/gi,
      explain: 'A database URI can contain credentials, hosts, database names or other connection details.', placeholder: '[DATABASE_URL_REDACTED]' },
    
    // ------------------------- PHI / BLOOD GROUP -------------------------
    {
      cat: 'Blood group / blood type',
      risk: 'high',

      // Explicitly labeled blood groups only.
      // Supports A+, A-, B+, B-, AB+, AB-, O+, O-.
      re: /\b(?:blood\s*(?:group|type)|blood\s*grp|ABO\s*(?:group|type)?|Rh(?:esus)?\s*(?:factor|type)?)\s*[:=]?\s*(?:AB|A|B|O)\s*[+-](?![A-Za-z0-9])/gi,
      explain: 'Blood group is sensitive health information, particularly when associated with an identifiable person.',
      placeholder: (m) => m.replace(/((?:[:=]\s*))(?:(?:AB|A|B|O)\s*[+-])$/i, '$1[BLOOD_GROUP_REDACTED]')
    },
    
    {
      cat: 'Generic secret assignment', risk: 'high',
      // Handles bare and compound names such as DB_PASSWORD=, SERVICE_TOKEN=,
      // CLIENT_SECRET:, api_key=, access_key=, passwd=, etc.
      re: /\b(?:[A-Za-z][A-Za-z0-9]*?[_-]?)?(?:api[_-]?key|secret|password|passwd|token|access[_-]?key)\s*([:=])\s*(["']?)([^\s"'`,;}\]]{8,})\2/gi,
      explain: 'The setting name and assigned value look like credential material.',
      placeholder: (m) => m.replace(/([:=])\s*(["']?)([^\s"'`,;}\]]{8,})\2$/i, '$1 $2[SECRET_REDACTED]$2')
    },

    { cat: 'Stripe API key', risk: 'high', re: /\bsk_(?:live|test)_[A-Za-z0-9]{16,}\b/g,
      explain: 'Looks like a Stripe secret key, which can create charges or access payment data.', placeholder: '[STRIPE_KEY_REDACTED]' },

    { cat: 'Google API key', risk: 'high', re: /\bAIza[0-9A-Za-z_-]{35}\b/g,
      explain: 'Looks like a Google API key, which may grant access to Google Cloud or Maps/Firebase services.', placeholder: '[GOOGLE_API_KEY_REDACTED]' },

    { cat: 'GitHub fine-grained token', risk: 'high', re: /\bgithub_pat_[A-Za-z0-9_]{20,}\b/g,
      explain: 'Looks like a GitHub fine-grained personal access token, which can grant scoped repository access.', placeholder: '[GITHUB_TOKEN_REDACTED]' },

    // ------------------------- CONTACT / PII -------------------------
    { cat: 'Email address', risk: 'med', re: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g,
      explain: 'An email address can identify or contact a person or organization.', placeholder: '[EMAIL_REDACTED]' },

    {
      cat: 'Indian mobile number', risk: 'med',
      re: /(?<!\d)(?:\+?91[-.\s]?|0)?[6-9]\d{4}[-.\s]?\d{5}(?!\d)/g,
      explain: 'Matches the format of an Indian mobile number, which is personal contact information.',
      placeholder: '[PHONE_REDACTED]'
    },

    { cat: 'Phone number', risk: 'med', re: /\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}\b/g,
      explain: 'Looks like a phone number associated with a real person.', placeholder: '[PHONE_REDACTED]' },

    {
      cat: 'Full name (labeled)', risk: 'med',
      // Context-aware: require an explicit name field to avoid flagging ordinary words.
      re: /\b(?:customer[ \t]+name|full[ \t]+name|patient[ \t]+name|employee[ \t]+name|student[ \t]+name|contact[ \t]+name|name)\s*[:=]\s*([A-Z][A-Za-z.'-]{1,30}(?:[ \t]+[A-Z][A-Za-z.'-]{1,30}){0,3})(?=[\r\n]|$)/gi,
      explain: 'A labeled person name can identify an individual, especially when combined with other fields.',
      placeholder: (m) => m.replace(/([:=]\s*)([A-Z][A-Za-z.'-]{1,30}(?:[ \t]+[A-Z][A-Za-z.'-]{1,30}){0,3})$/i, '$1[NAME_REDACTED]')
    },

    {
      cat: 'Date of birth', risk: 'med',
      re: /\b(?:date\s+of\s+birth|dob|birth\s*date)\s*[:=]\s*(\d{1,2}[\/-](?:\d{1,2}|[A-Za-z]{3,9})[\/-]\d{2,4}|\d{1,2}\s+[A-Za-z]{3,9}\s+\d{4})\b/gi,
      explain: 'A date of birth is personal information that can help identify or verify a person.',
      placeholder: (m) => m.replace(/([:=]\s*)(\d{1,2}[\/-](?:\d{1,2}|[A-Za-z]{3,9})[\/-]\d{2,4}|\d{1,2}\s+[A-Za-z]{3,9}\s+\d{4})$/i, '$1[DOB_REDACTED]')
    },

    {
      cat: 'Place of birth', risk: 'med',
      re: /\b(?:place[ \t]+of[ \t]+birth|birthplace|born[ \t]+in)\s*[:=]\s*([^\n]{2,120})/gi,
      explain: 'Place of birth is personal information that can contribute to identifying or profiling an individual.',
      placeholder: (m) => m.replace(/([:=]\s*)[^\n]{2,120}$/i, '$1[PLACE_OF_BIRTH_REDACTED]')
    },

    {
      cat: 'Home / postal address (labeled)', risk: 'med',
      re: /(?<!IP[ \t])(?<!Email[ \t])\b(?:home[ \t]+address|postal[ \t]+address|residential[ \t]+address|address)\s*[:=]\s*(?!\d{1,3}(?:\.\d{1,3}){3}\b)([^\n]{8,160})/gi,
      explain: 'A labeled street or residential address can locate a specific person.',
      placeholder: (m) => m.replace(/([:=]\s*)([^\n]{8,160})$/i, '$1[ADDRESS_REDACTED]')
    },

    // ------------------------- INDIAN IDENTIFIERS -------------------------
    {
      cat: 'Aadhaar number (IN, labeled)', risk: 'high',
      // Explicit Aadhaar/UID labels are enough to surface a candidate,
      // including synthetic values that fail checksum validation.
      re: /\b(?:aadhaar|aadhar|uid(?:ai)?)\s*(?:number|no\.?|id)?\s*[:=]\s*[2-9]\d{3}(?:[\s-]?\d{4}){2}\b/gi,
      explain: 'An explicitly labeled Aadhaar/UID value is highly sensitive. The guard flags the labeled value even when checksum validation cannot confirm it.',
      placeholder: (m) => {
        const sep = Math.max(m.lastIndexOf(':'), m.lastIndexOf('='));
        if (sep < 0) return '[AADHAAR_REDACTED]';
        const ws = (m.slice(sep + 1).match(/^\s*/) || [''])[0];
        return m.slice(0, sep + 1) + ws + '[AADHAAR_REDACTED]';
      }
    },
    
    {
      cat: 'Voter ID / EPIC (IN)',
      risk: 'high',
      re: /\b(?:voter\s*(?:id|identity|card)|epic)\s*(?:number|no\.?|id)?\s*[:=]\s*[A-Z]{3}[A-Z0-9]{7,10}\b/gi,
      explain: 'A labeled Indian Voter ID (EPIC) is a government identity identifier and sensitive personal information.',
      placeholder: (m) => m.replace(/([:=]\s*)[A-Z]{3}[A-Z0-9]{7,10}\b/i,'$1[VOTER_ID_REDACTED]')
    },
    
    {
      cat: 'Aadhaar number (IN)', risk: 'high',
      // Unlabeled 12-digit candidates MUST pass Verhoeff validation. This
      // prevents arbitrary 12-digit numbers from becoming Aadhaar findings.
      // Continuous, space-separated and hyphen-separated forms are supported.
      re: /\b[2-9]\d{3}(?:[\s-]?\d{4}){2}\b/g,
      explain: 'Matches a 12-digit Aadhaar-format identifier after Verhoeff validation.',
      placeholder: '[AADHAAR_REDACTED]',
      validate: m => verhoeffValidate(m.replace(/[\s-]/g, ''))
    },

    {
      cat: 'National ID (labeled)', risk: 'high',
      re: /\b(?:national[ \t]+id|national[ \t]+identification[ \t]+number|identity[ \t]+number|government[ \t]+id)\s*[:=]\s*[A-Za-z0-9-]{6,24}\b/gi,
      explain: 'A labeled government/national identity number is highly sensitive personal information.',
      placeholder: (m) => m.replace(/([:=]\s*)[A-Za-z0-9-]{6,24}\b/i, '$1[NATIONAL_ID_REDACTED]')
    },

    {
      cat: 'PAN number (IN)', risk: 'high',
      re: /\b(?:PAN|permanent[ \t]+account[ \t]+number)\s*(?:number|no\.?)?\s*[:=]?\s*[A-Z]{5}\d{4}[A-Z]\b|\b[A-Z]{5}\d{4}[A-Z]\b/gi,
      explain: 'Matches the format of an Indian Permanent Account Number (PAN), a tax/identity identifier.',
      placeholder: (m) => /^[A-Z]{5}\d{4}[A-Z]$/i.test(m) ? '[PAN_REDACTED]' : m.replace(/([:=]\s*)[A-Z]{5}\d{4}[A-Z]\b/i, '$1[PAN_REDACTED]')
    },

    {
      cat: 'Passport number (IN)', risk: 'high',
      re: /\b(?:passport\s*(?:number|no\.?)?\s*[:=]\s*)?[A-PR-WY][0-9]{7}\b/gi,
      explain: 'Matches the common Indian passport number format.',
      placeholder: (m) => /^[A-PR-WY][0-9]{7}$/i.test(m) ? '[PASSPORT_REDACTED]' : m.replace(/([:=]\s*)[A-PR-WY][0-9]{7}\b/i, '$1[PASSPORT_REDACTED]')
    },

    {
      cat: "Driver's license (IN)", risk: 'high',
      re: /\b(?:driver'?s?\s+license|driving\s+license|dl)\s*(?:number|no\.?)?\s*[:=]?\s*[A-Z]{2}[-\s]?[0-9A-Z]{1,3}[-\s]?(?:19|20)\d{2}[-\s]?\d{6,11}\b/gi,
      explain: "Matches a labeled Indian driver's license number format.",
      placeholder: (m) => m.replace(/([:=]\s*)[A-Z]{2}[-\s]?[0-9A-Z]{1,3}[-\s]?(?:19|20)\d{2}[-\s]?\d{6,11}\b/i, '$1[LICENSE_REDACTED]')
    },

    {
      cat: 'Employee ID', risk: 'med',
      // Labels or common enterprise patterns: EMP-2026-0147, EMP20260147, etc.
      re: /\b(?:(?:employee|staff|worker)\s*(?:id|number|no\.?)|emp\s*id)\s*[:=]?\s*(?:EMP[-_ ]?)?[A-Z0-9]{2,6}[-_]\d{2,4}[-_]\d{2,8}\b|\bEMP[-_]\d{2,4}[-_]\d{2,8}\b/gi,
      explain: 'An employee identifier is internal personal information and can link records to a specific staff member.',
      placeholder: (m) => /^EMP[-_]\d{2,4}[-_]\d{2,8}$/i.test(m) ? '[EMPLOYEE_ID_REDACTED]' : m.replace(/([:=]\s*)(?:EMP[-_ ]?)?[A-Z0-9]{2,6}[-_]\d{2,4}[-_]\d{2,8}\b/i, '$1[EMPLOYEE_ID_REDACTED]')
    },

    // ------------------------- FINANCIAL -------------------------
    {
      cat: 'Bank account number', risk: 'high',
      re: /\b(?:bank\s*account|account\s*(?:no\.?|number)|a\/?c\s*no\.?)\s*[:=]?\s*(\d{8,18})\b/gi,
      explain: 'A labeled bank account number is financial information that should not be disclosed to a public AI service.',
      placeholder: (m) => m.replace(/\d{8,18}\b/, '[ACCOUNT_REDACTED]')
    },

    {
      cat: 'IFSC code (IN)', risk: 'med',
      re: /\b(?:IFSC\s*(?:code)?\s*[:=]\s*)?[A-Z]{4}0[A-Z0-9]{6}\b/gi,
      explain: 'An Indian IFSC code identifies a bank branch and can expose financial-routing context.',
      placeholder: (m) => /^[A-Z]{4}0[A-Z0-9]{6}$/i.test(m) ? '[IFSC_REDACTED]' : m.replace(/([:=]\s*)[A-Z]{4}0[A-Z0-9]{6}\b/i, '$1[IFSC_REDACTED]')
    },

    {
      cat: 'UPI ID', risk: 'med',
      re: /\b(?:upi\s*(?:id|handle)?\s*[:=]\s*)?[A-Za-z0-9._-]{2,}@[A-Za-z][A-Za-z0-9.-]{2,}\b/gi,
      explain: 'A UPI handle can identify a person or business and facilitate financial transactions.',
      placeholder: (m) => /^[A-Za-z0-9._-]{2,}@[A-Za-z][A-Za-z0-9.-]{2,}$/i.test(m) ? '[UPI_ID_REDACTED]' : m.replace(/([:=]\s*)[A-Za-z0-9._-]{2,}@[A-Za-z][A-Za-z0-9.-]{2,}\b/i, '$1[UPI_ID_REDACTED]')
    },

    {
      cat: 'Financial statement / tax information', risk: 'high',
      re: /\b(?:salary|compensation|credit[ \t]+history|tax[ \t]+return|financial[ \t]+statement|bank[ \t]+statement|credit[ \t]+report)\s*[:=]\s*[^\n]{3,220}/gi,
      explain: 'Financial or tax information can expose sensitive personal or organizational financial data.',
      placeholder: (m) => m.replace(/([:=]\s*)[^\n]{3,220}$/i, '$1[FINANCIAL_DATA_REDACTED]')
    },

    {
      cat: 'Card security data', risk: 'high',
      re: /\b(?:cvv|cvc|security[ \t]+code|card[ \t]+expiry|expiration[ \t]+date)\s*[:=]\s*[A-Za-z0-9\/ -]{3,20}\b/gi,
      explain: 'Card security codes or expiry information are sensitive payment-card data.',
      placeholder: (m) => m.replace(/([:=]\s*)[A-Za-z0-9\/ -]{3,20}\b/i, '$1[CARD_SECURITY_DATA_REDACTED]')
    },

    { cat: 'Credit card number', risk: 'high', re: /\b(?:\d[ -]*?){13,16}\b/g,
      explain: 'A number sequence may represent a payment card. The Luhn check reduces false positives.', placeholder: '[CARD_REDACTED]', validate: m => luhnCheck(m.replace(/[ -]/g, '')) },

    // ------------------------- HEALTH / PHI -------------------------
    {
      cat: 'Health record identifier', risk: 'high',
      re: /\b(?:medical\s*(?:record|record\s*number|id)|patient\s*(?:id|number|no\.?)|mrn|health\s*(?:record|id)|insurance\s*(?:id|number)|policy\s*(?:number|no\.?))\s*[:=]\s*[A-Za-z0-9-]{4,24}\b/gi,
      explain: 'A labeled medical, patient, insurance, or health-record identifier is protected personal health information.',
      placeholder: (m) => m.replace(/([:=]\s*)[A-Za-z0-9-]{4,24}\b/i, '$1[HEALTH_ID_REDACTED]')
    },

    {
      cat: 'Health information (labeled)', risk: 'high',
      re: /\b(?:diagnosis|medical\s*history|clinical\s*history|prescription|medication|insurance\s*claim|health\s*condition)\s*[:=]\s*[^\n]{3,180}/gi,
      explain: 'Labeled medical or insurance information can reveal a person’s health status or care history.',
      placeholder: (m) => m.replace(/([:=]\s*)[^\n]{3,180}$/i, '$1[HEALTH_INFO_REDACTED]')
    },

    {
      cat: 'Insurance / policy information', risk: 'high',
      re: /\b(?:insurance[ \t]+(?:policy|claim)|policy[ \t]+(?:number|no\.?)|health[ \t]+insurance)\s*[:=]\s*[^\n]{3,180}/gi,
      explain: 'Insurance policy and claim information can expose sensitive financial or health-related data.',
      placeholder: (m) => m.replace(/([:=]\s*)[^\n]{3,180}$/i, '$1[INSURANCE_DATA_REDACTED]')
    },

    // ------------------------- TECHNICAL / INFRASTRUCTURE -------------------------
    { cat: 'IPv4 address', risk: 'med', re: /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g,
      explain: 'An IP address can reveal infrastructure details, especially when it is internal.', placeholder: '[IP_REDACTED]' },

    { cat: 'Internal URL / hostname', risk: 'med', re: /\bhttps?:\/\/[^\s/]+(?:internal|intranet|corp|localhost|\.local)(?::\d+)?(?:\/[^\s]*)?\b/gi,
      explain: 'Looks like an internal or private service endpoint that could reveal organizational infrastructure.', placeholder: '[INTERNAL_URL_REDACTED]' },

    // ------------------------- BIOMETRIC / OTHER IDENTIFIERS -------------------------
    {
      cat: 'Biometric identifier (labeled)', risk: 'high',
      re: /\b(?:fingerprint|retina|iris|face\s*embedding|facial\s*geometry|biometric\s*(?:id|template))\s*[:=]\s*[^\n]{3,200}/gi,
      explain: 'Labeled biometric information is highly sensitive and can uniquely identify a person.',
      placeholder: (m) => m.replace(/([:=]\s*)[^\n]{3,200}$/i, '$1[BIOMETRIC_DATA_REDACTED]')
    },

    // ------------------------- CORPORATE / PROPRIETARY -------------------------
    {
      cat: 'Confidential / internal business data (labeled)', risk: 'high',
      re: /\b(?:CONFIDENTIAL|INTERNAL\s+ONLY|PRIVATE\s+AND\s+CONFIDENTIAL|PROPRIETARY|SECRET\s+PROJECT|UNRELEASED|NDA\s+MATERIAL|BOARD\s+MINUTES|LEGAL\s+CONFIDENTIAL)\s*[:\-]?\s*[^\n]{0,220}/gi,
      explain: 'The text is explicitly marked as confidential, internal, proprietary or otherwise restricted business information.',
      placeholder: (m) => m.replace(/^(\s*(?:CONFIDENTIAL|INTERNAL\s+ONLY|PRIVATE\s+AND\s+CONFIDENTIAL|PROPRIETARY|SECRET\s+PROJECT|UNRELEASED|NDA\s+MATERIAL|BOARD\s+MINUTES|LEGAL\s+CONFIDENTIAL)\s*[:\-]?\s*)[^\n]{0,220}$/i, '$1[CORPORATE_DATA_REDACTED]')
    },

    {
      cat: 'Customer database / list reference', risk: 'high',
      re: /\b(?:customer\s+(?:database|list|records)|client\s+(?:database|list|records)|customer\s+export)\s*[:=]\s*[^\n]{3,220}/gi,
      explain: 'Customer databases and lists are sensitive corporate and personal data that should not be exposed to public AI services.',
      placeholder: (m) => m.replace(/([:=]\s*)[^\n]{3,220}$/i, '$1[CUSTOMER_DATA_REDACTED]')
    },

    {
      cat: 'Project codename / unreleased roadmap', risk: 'med',
      re: /\b(?:project\s+codename|internal\s+project|unreleased\s+product|product\s+roadmap|launch\s+date|go[\s-]?to[\s-]?market\s+plan)\s*[:=]\s*[^\n]{3,220}/gi,
      explain: 'Internal project names and unreleased product plans can expose proprietary business information.',
      placeholder: (m) => m.replace(/([:=]\s*)[^\n]{3,220}$/i, '$1[PROPRIETARY_DATA_REDACTED]')
    },

    {
      cat: 'Source code / proprietary logic (labeled)', risk: 'med',
      re: /\b(?:proprietary\s+source\s+code|internal\s+algorithm|trade\s+secret|patent\s+d?raft|confidential\s+source\s+code)\s*[:=]\s*[^\n]{3,260}/gi,
      explain: 'Explicitly labeled proprietary source code or trade-secret material is sensitive intellectual property.',
      placeholder: (m) => m.replace(/([:=]\s*)[^\n]{3,260}$/i, '$1[PROPRIETARY_CODE_REDACTED]')
    }
  ];

  function luhnCheck(num) {
    if (!/^\d{13,19}$/.test(num)) return false;
    let sum = 0, alt = false;
    for (let i = num.length - 1; i >= 0; i--) {
      let n = parseInt(num[i], 10);
      if (alt) { n *= 2; if (n > 9) n -= 9; }
      sum += n; alt = !alt;
    }
    return sum % 10 === 0;
  }

  // Verhoeff checksum: used to validate Indian Aadhaar numbers (last digit is
  // a check digit computed with this algorithm). Standard multiplication (d),
  // permutation (p) tables.
  const VERHOEFF_D = [
    [0,1,2,3,4,5,6,7,8,9],[1,2,3,4,0,6,7,8,9,5],[2,3,4,0,1,7,8,9,5,6],
    [3,4,0,1,2,8,9,5,6,7],[4,0,1,2,3,9,5,6,7,8],[5,9,8,7,6,0,4,3,2,1],
    [6,5,9,8,7,1,0,4,3,2],[7,6,5,9,8,2,1,0,4,3],[8,7,6,5,9,3,2,1,0,4],
    [9,8,7,6,5,4,3,2,1,0]
  ];
  const VERHOEFF_P = [
    [0,1,2,3,4,5,6,7,8,9],[1,5,7,6,2,8,3,0,9,4],[5,8,0,3,7,9,6,1,4,2],
    [8,9,1,6,0,4,3,5,2,7],[9,4,5,3,1,2,6,8,7,0],[4,2,8,6,5,7,3,9,0,1],
    [2,7,9,3,8,0,6,4,1,5],[7,0,4,6,9,1,3,2,5,8]
  ];

  function verhoeffValidate(numStr) {
    if (!/^\d{12}$/.test(numStr)) return false;
    let c = 0;
    const digits = numStr.split('').reverse().map(Number);
    for (let i = 0; i < digits.length; i++) c = VERHOEFF_D[c][VERHOEFF_P[i % 8][digits[i]]];
    return c === 0;
  }

  // Build a scan-safe shadow string while preserving offsets into the
  // original prompt. This prevents invisible Unicode characters from
  // defeating every regex without corrupting redaction positions.
  function buildScanView(text) {
    const chars = [];
    const map = [];
    const invisible = /[\u200B-\u200D\u2060\uFEFF\u00AD\u202A-\u202E\u2066-\u2069]/;
    for (let i = 0; i < text.length; i++) {
      if (invisible.test(text[i])) continue;
      chars.push(text[i]);
      map.push(i);
    }
    return { text: chars.join(''), map };
  }

  function scan(text) {
    const matches = [];
    const view = buildScanView(text);

    for (const rule of RULES) {
      rule.re.lastIndex = 0;
      let m;
      while ((m = rule.re.exec(view.text)) !== null) {
        if (rule.validate && !rule.validate(m[0])) continue;

        const shadowStart = m.index;
        const shadowEnd = m.index + m[0].length;
        const start = view.map[shadowStart];
        const end = view.map[shadowEnd - 1] + 1;
        const raw = text.slice(start, end);

        matches.push({ start, end, raw, rule });
        if (rule.re.lastIndex === m.index) rule.re.lastIndex++;
      }
    }
    matches.sort((a, b) => a.start - b.start || (b.end - b.start) - (a.end - a.start));
    const kept = [];
    let lastEnd = -1;
    for (const m of matches) {
      if (m.start >= lastEnd) { kept.push(m); lastEnd = m.end; }
    }
    return kept;
  }

  function rewritePlainText(text, matches) {
    let out = '', cursor = 0;
    for (const m of matches) {
      out += text.slice(cursor, m.start);
      out += typeof m.rule.placeholder === 'function' ? m.rule.placeholder(m.raw) : m.rule.placeholder;
      cursor = m.end;
    }
    return out + text.slice(cursor);
  }

  function summarize(matches) {
    return {
      total: matches.length,
      high: matches.filter(m => m.rule.risk === 'high').length,
      medium: matches.filter(m => m.rule.risk === 'med').length,
      categories: [...new Set(matches.map(m => m.rule.cat))]
    };
  }

  window.PDLGScanner = Object.freeze({ scan, rewritePlainText, summarize });
})();
