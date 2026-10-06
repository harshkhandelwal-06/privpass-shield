from __future__ import annotations
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HTML = (ROOT / 'static' / 'index.html').read_text(encoding='utf-8')
JS = (ROOT / 'static' / 'app.js').read_text(encoding='utf-8')

required_ids = [
    'pw-input','pw-score','pw-label','pw-verdict','pw-bar','pw-length','pw-guesses','pw-bits',
    'pw-pattern','pw-context','pw-why','pw-reasons','hibp-prefix','pw-result','hibp-check',
    'analyze-password','generate-pass','generator-mode','generator-length','copy-pass','clear-password',
    'run-benchmark','benchmark-results','browse-repo','repo-file','findings-list','user-list','audit-list',
    'view-vault','vault-unlock','vault-master','vault-list','vault-count','vault-weak','vault-due','vault-reused','vault-posture',
    'vault-add','vault-editor','vault-save','vault-password','vault-entry-strength-bar','vault-export','vault-import-btn','vault-import-file','vault-reminder-enable',
    'audit-sample','audit-browse','audit-file','audit-rows','audit-headline',
    'form-signin','form-signup','form-reset','account-menu','sign-out','neural-panel','ai-coach-btn','view-ai','copilot-form','report-generate','anomaly-simulate','ai-triage',
    'bell','bell-list','honey-form','honey-list','gh-form','security-modal','form-security','passkey-add','passkey-signin','proof-fab','proof-drawer','tour','tour-start','sla-overdue'
]
missing = [x for x in required_ids if not re.search(r'id=[\"\']'+re.escape(x)+r'[\"\']', HTML)]
if missing:
    raise SystemExit('UI_CHECK_FAIL missing ids: ' + ', '.join(missing))

# The old 5.2 bug was two functions named analyzePassword; keep the pure core and event wrapper distinct.
if len(re.findall(r'function\s+analyzePassword\s*\(', JS)) != 0:
    raise SystemExit('UI_CHECK_FAIL stale analyzePassword function name detected')
if len(re.findall(r'function\s+analyzePasswordCore\s*\(', JS)) != 1:
    raise SystemExit('UI_CHECK_FAIL analyzePasswordCore must exist exactly once')
if len(re.findall(r'function\s+refreshPasswordAnalysis\s*\(', JS)) != 1:
    raise SystemExit('UI_CHECK_FAIL refreshPasswordAnalysis must exist exactly once')

if 'demo-notes' in HTML or 'What to say:' in HTML or 'What not to claim:' in HTML:
    raise SystemExit('UI_CHECK_FAIL removed Demo Center speaker-coaching block is present')
for required_path in ['tools/secret_scan.py', 'tools/install_precommit.py', '.githooks/pre-commit', '.github/workflows/secretguard.yml', 'docs/SECRETGUARD-CI.md', 'scripts/RUN-SECRETGUARD-DEMO.bat', 'scripts/INSTALL-SECRETGUARD-HOOK.bat', 'scripts/RUN-SECRETGUARD-HOOK-DEMO.bat', 'START-PRIVPASS.bat', 'demo-assets/PrivPass-Clean-Demo-Repo.zip']:
    if not (ROOT / required_path).exists():
        raise SystemExit('UI_CHECK_FAIL missing SecretGuard developer asset: ' + required_path)
CSS = (ROOT / 'static' / 'styles.css').read_text(encoding='utf-8')
MOTION = (ROOT / 'static' / 'motion.js').read_text(encoding='utf-8')

# 7.0 design system guards: theme tokens, self-hosted fonts, behaviour-critical state classes.
for token in [':root[data-theme="light"]', '--accent:', '--surface:', '@font-face', '/static/fonts/inter-tight.woff2']:
    if token not in CSS:
        raise SystemExit(f'UI_CHECK_FAIL design token missing: {token}')
for state_rule in ['.hidden{display:none!important}', '.view.active{display:block}', '.modal.open{display:flex', '.toast.show', '.auth-status.show',
                   '.account-menu.open .account-dropdown', '.bell.open .bell-dropdown', '.proof-drawer.open', '.dropzone.drag']:
    if state_rule not in CSS:
        raise SystemExit(f'UI_CHECK_FAIL behaviour-critical CSS rule missing: {state_rule}')
for font in ['inter-tight.woff2', 'instrument-serif-italic.woff2', 'jetbrains-mono.woff2']:
    if not (ROOT / 'static' / 'fonts' / font).exists():
        raise SystemExit(f'UI_CHECK_FAIL missing bundled font: {font}')
if 'prefers-reduced-motion' not in CSS or 'prefers-reduced-motion' not in MOTION:
    raise SystemExit('UI_CHECK_FAIL reduced-motion support missing')
if '/static/motion.js' not in HTML:
    raise SystemExit('UI_CHECK_FAIL motion layer not loaded')

for needle in ['lookupHibp', 'id="pw-verdict"', 'id="run-benchmark"', 'generator-length', 'deriveVaultKey', 'encryptVaultPayload', 'decryptVaultPayload', 'exportEncryptedVault', 'importEncryptedVault', 'rotateVaultItem', 'removeLegacyDemoGuidance']:
    if needle not in (JS + HTML):
        raise SystemExit(f'UI_CHECK_FAIL missing feature marker: {needle}')


# SecretGuard findings must be expandable and evidence-rich, without duplicating scanner logic.
for marker in ['finding-details', 'finding-summary', 'finding-detail-body', 'finding-evidence-grid', 'finding-detail-grid', 'finding-remediation', 'finding-search', 'finding-severity', 'finding-status', 'filteredFindings', 'findingWhy', 'findingNextStep']:
    if marker not in (JS + HTML + CSS):
        raise SystemExit(f'UI_CHECK_FAIL missing expandable SecretGuard feature marker: {marker}')
if len(re.findall(r'function\s+renderFindings\s*\(', JS)) != 1:
    raise SystemExit('UI_CHECK_FAIL renderFindings must exist exactly once')
if '.finding-details[open]' not in CSS or '.findings-toolbar' not in CSS or '.finding-evidence-grid' not in CSS:
    raise SystemExit('UI_CHECK_FAIL SecretGuard expandable findings CSS missing')

print('UI_CHECK_OK')

# Landing page and navigation must keep their hooks.
for marker in ['id="hero-try"', 'id="menu-overlay"', 'id="nav-indicator"', 'id="story-visual"', 'id="m-checks"']:
    if marker not in HTML:
        raise SystemExit(f'UI_CHECK_FAIL missing landing marker: {marker}')
# 7.1: exposure map, workspaces, word & name attack model, password-manager support.
for marker in ['id="xp-svg"', 'id="xp-paths"', 'id="xp-controls"', 'id="ws-pill"', 'id="sec-demo-note"', 'data-ws-only="demo"',
               '/static/ml/structure-model.js', '/static/exposure.js', 'id="signup-pm-note"', 'data-close-dropdown']:
    if marker not in HTML:
        raise SystemExit(f'UI_CHECK_FAIL missing 7.1 marker: {marker}')
if not (ROOT / 'static' / 'ml' / 'words-names.txt.gz').exists():
    raise SystemExit('UI_CHECK_FAIL missing word & name list for the structure model')
if 'Briefs #20 + #24' in HTML:
    raise SystemExit('UI_CHECK_FAIL hero meta text should be removed')
print('UI_CSS_HARDENING_OK')
