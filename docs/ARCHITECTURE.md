# Architecture

```text
Browser
  ├─ Password analysis (local)
  ├─ Web Crypto SHA-1
  ├─ HIBP 5-char range query
  └─ Browser-derived credential verifier
          │
          ▼
      FastAPI API
       ├─ Auth / sessions
       ├─ MFA / reset
       ├─ Aggregate password events
       ├─ SecretGuard scan API
       └─ Admin command center
          │
     ┌────┴─────────┐
     ▼              ▼
 PostgreSQL       Redis
     │              │
     └──────┬───────┘
            ▼
      Exposure / Incident layer
```

### Local mode
SQLite is intentionally used to reduce setup failure modes.

### Production mode
PostgreSQL and Redis are the shared-state path. The API is stateless apart from the database/Redis layers, so multiple workers can sit behind a load balancer.

### Demo separation
The development-only `/api/demo/*` endpoints expose synthetic credentials and a fake repository. These endpoints are disabled in production.

## SecretGuard developer workflow

The SecretGuard detection engine is shared by all entry points:

```text
Web ZIP Scan ─┐
CLI Scan ─────┼─> app.scanner ─> Pattern + Context + Entropy + Validity ─> Deduplicate ─> Findings/SARIF
Pre-commit ───┤
GitHub CI ────┘
```

The staged-file mode reads the Git index, so a developer cannot accidentally bypass the hook by scanning an unsaved working-tree version. The GitHub workflow uploads SARIF to Code Scanning and fails the job on verified HIGH/CRITICAL findings. GitHub supports third-party SARIF uploads via `github/codeql-action/upload-sarif`. citeturn229006search7


## Live exposure correlation

The Exposure Graph and Incident Center do not maintain a duplicate incident dataset. They read from the existing `Scan`, `SecretFinding`, `PasswordEvent`, `User`, and `Session` records. After a repository ZIP is scanned, the latest persisted scan becomes the source for both views. Finding lifecycle transitions update the same `SecretFinding.status`, and the two views refresh after a scan or transition.

The Exposure Graph derives an operator-facing risk score from the latest scan severity, password telemetry, MFA state, and active sessions. The Incident Center groups the latest scan's findings into action-needed, remediation, and verified columns while keeping per-finding lifecycle status.
