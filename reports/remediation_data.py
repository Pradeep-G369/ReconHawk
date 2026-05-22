# ReconHawk - Remediation Data
# Maps every finding type to a clear remediation action
# Used by PDF generator to build remediation checklist

REMEDIATION_MAP = {
    "Strict-Transport-Security": {
        "title"   : "Enable HTTP Strict Transport Security (HSTS)",
        "steps"   : [
            "Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains",
            "Configure in web server (Apache/Nginx) or application layer",
            "Test using https://hstspreload.org",
        ],
        "priority": "HIGH",
        "effort"  : "Low — single line config change",
    },
    "Content-Security-Policy": {
        "title"   : "Implement Content Security Policy (CSP)",
        "steps"   : [
            "Start with: Content-Security-Policy: default-src 'self'",
            "Test with browser console for blocked resources",
            "Gradually tighten policy using report-only mode first",
        ],
        "priority": "HIGH",
        "effort"  : "Medium — requires testing across all pages",
    },
    "X-Frame-Options": {
        "title"   : "Prevent Clickjacking with X-Frame-Options",
        "steps"   : [
            "Add header: X-Frame-Options: DENY",
            "Or use: X-Frame-Options: SAMEORIGIN if frames needed",
        ],
        "priority": "MEDIUM",
        "effort"  : "Low — single line config change",
    },
    "SPF": {
        "title"   : "Add SPF DNS Record to prevent email spoofing",
        "steps"   : [
            "Add TXT record: v=spf1 include:_spf.yourmailprovider.com -all",
            "Use -all (hardfail) not ~all (softfail)",
            "Test using https://mxtoolbox.com/spf.aspx",
        ],
        "priority": "HIGH",
        "effort"  : "Low — DNS record change",
    },
    "DMARC": {
        "title"   : "Add DMARC policy to enforce email authentication",
        "steps"   : [
            "Add TXT record on _dmarc.yourdomain.com",
            "Start with: v=DMARC1; p=none; rua=mailto:dmarc@yourdomain.com",
            "Graduate to p=quarantine then p=reject after monitoring",
        ],
        "priority": "HIGH",
        "effort"  : "Low — DNS record change",
    },
    "Certificate expired": {
        "title"   : "Renew SSL/TLS Certificate immediately",
        "steps"   : [
            "Use Let's Encrypt for free certificates (certbot)",
            "Run: certbot renew",
            "Set up auto-renewal cron job",
        ],
        "priority": "CRITICAL",
        "effort"  : "Low — automated with certbot",
    },
    "Self-signed certificate": {
        "title"   : "Replace self-signed certificate with CA-signed cert",
        "steps"   : [
            "Use Let's Encrypt: certbot --nginx -d yourdomain.com",
            "Or purchase certificate from trusted CA",
            "Update web server config to use new cert",
        ],
        "priority": "HIGH",
        "effort"  : "Low — free with Let's Encrypt",
    },
    "/.git/HEAD": {
        "title"   : "Remove exposed Git repository immediately",
        "steps"   : [
            "Block access in Nginx: location ~ /\\.git { deny all; }",
            "Block in Apache: RedirectMatch 404 /\\.git",
            "Rotate any secrets/keys that may have been exposed",
            "Check git history for committed credentials",
        ],
        "priority": "CRITICAL",
        "effort"  : "Low — web server config change",
    },
    "/.env": {
        "title"   : "Remove exposed .env file immediately",
        "steps"   : [
            "Move .env outside web root",
            "Block in web server config: deny access to dotfiles",
            "Rotate ALL credentials/API keys in the file",
            "Audit access logs for previous reads of this file",
        ],
        "priority": "CRITICAL",
        "effort"  : "Medium — requires credential rotation",
    },
    "Default credentials": {
        "title"   : "Change all default credentials immediately",
        "steps"   : [
            "Change admin password to strong random string (20+ chars)",
            "Disable default accounts where possible",
            "Implement account lockout after 5 failed attempts",
            "Enable multi-factor authentication",
        ],
        "priority": "CRITICAL",
        "effort"  : "Low — immediate config change",
    },
    "CVE": {
        "title"   : "Patch vulnerable software versions",
        "steps"   : [
            "Check vendor advisory for patch availability",
            "Update software to latest patched version",
            "If patch unavailable, implement WAF rule as temporary mitigation",
            "Test in staging environment before production deployment",
        ],
        "priority": "CRITICAL",
        "effort"  : "Medium — requires testing after update",
    },
}

GENERAL_CHECKLIST = [
    {
        "item"    : "Keep all software and dependencies updated",
        "priority": "HIGH",
        "effort"  : "Low",
    },
    {
        "item"    : "Implement Web Application Firewall (WAF)",
        "priority": "HIGH",
        "effort"  : "Medium",
    },
    {
        "item"    : "Enable comprehensive logging and monitoring",
        "priority": "HIGH",
        "effort"  : "Medium",
    },
    {
        "item"    : "Conduct regular penetration testing",
        "priority": "MEDIUM",
        "effort"  : "High",
    },
    {
        "item"    : "Implement principle of least privilege",
        "priority": "MEDIUM",
        "effort"  : "Medium",
    },
    {
        "item"    : "Set up vulnerability disclosure policy",
        "priority": "LOW",
        "effort"  : "Low",
    },
]
