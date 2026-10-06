from __future__ import annotations

import argparse
import shutil
import stat
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HOOK_SOURCE = ROOT / ".githooks" / "pre-commit"


def repo_root(target: Path) -> Path:
    try:
        raw = subprocess.check_output(
            ["git", "-C", str(target), "rev-parse", "--show-toplevel"],
            text=True,
            stderr=subprocess.STDOUT,
        ).strip()
    except (OSError, subprocess.CalledProcessError) as exc:
        raise RuntimeError(f"{target} is not a Git repository or Git is unavailable") from exc
    return Path(raw).resolve()


def build_hook(project_root: Path) -> str:
    project = str(project_root.resolve()).replace("\\", "/").replace("'", "'\\''")
    return f"""#!/bin/sh
set -eu
PROJECT_ROOT='{project}'
if [ -x \"$PROJECT_ROOT/.venv/Scripts/python.exe\" ]; then
  PY=\"$PROJECT_ROOT/.venv/Scripts/python.exe\"
elif command -v python3 >/dev/null 2>&1; then
  PY=\"$(command -v python3)\"
elif command -v python >/dev/null 2>&1; then
  PY=\"$(command -v python)\"
elif command -v py >/dev/null 2>&1; then
  PY=\"$(command -v py)\"
else
  echo \"PrivPass SecretGuard: Python 3 is required.\" >&2
  exit 1
fi
\"$PY\" \"$PROJECT_ROOT/tools/secret_scan.py\" --staged --fail-on high --min-confidence 0.80
"""


def install(repo: Path) -> Path:
    target_root = repo_root(repo)
    hooks_dir = target_root / ".git" / "hooks"
    hooks_dir.mkdir(parents=True, exist_ok=True)
    hook_target = hooks_dir / "pre-commit"
    if hook_target.exists():
        backup = hooks_dir / "pre-commit.privpass-backup"
        if not backup.exists():
            shutil.copy2(hook_target, backup)
            print(f"Existing hook backed up to {backup}")
    hook_target.write_text(build_hook(ROOT), encoding="utf-8", newline="\n")
    hook_target.chmod(hook_target.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    print(f"PrivPass SecretGuard pre-commit hook installed in: {target_root}")
    print("Commits will be blocked on verified HIGH/CRITICAL secret findings (>=80% confidence).")
    return target_root


def create_demo_repo() -> Path:
    target = ROOT / "data" / "precommit-demo-repo"
    target.mkdir(parents=True, exist_ok=True)
    try:
        repo_root(target)
        return target
    except RuntimeError:
        pass
    try:
        subprocess.run(["git", "init"], cwd=target, check=True)
        subprocess.run(["git", "config", "user.email", "secretguard-demo@local"], cwd=target, check=True)
        subprocess.run(["git", "config", "user.name", "SecretGuard Demo"], cwd=target, check=True)
        (target / "README.md").write_text("Synthetic SecretGuard pre-commit demo repository.\n", encoding="utf-8")
        subprocess.run(["git", "add", "README.md"], cwd=target, check=True)
        subprocess.run(["git", "commit", "-m", "Initialize SecretGuard demo"], cwd=target, check=True, stdout=subprocess.DEVNULL)
        print(f"Created demo Git repository: {target}")
        return target
    except (OSError, subprocess.CalledProcessError) as exc:
        raise RuntimeError("Git is required to create the SecretGuard demo repository") from exc


def main() -> int:
    parser = argparse.ArgumentParser(description="Install the PrivPass SecretGuard pre-commit wrapper into a Git repository.")
    parser.add_argument("--repo", type=Path, default=ROOT, help="Target Git repository")
    parser.add_argument("--demo", action="store_true", help="Create/use the bundled local Git test repository")
    args = parser.parse_args()
    if not HOOK_SOURCE.exists():
        print(f"ERROR: missing hook template: {HOOK_SOURCE}", file=sys.stderr)
        return 2
    target = create_demo_repo() if args.demo else args.repo.resolve()
    try:
        install(target)
    except RuntimeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    if args.demo:
        print(f"Demo repo ready: {target}")
        print("Next: run RUN-SECRETGUARD-HOOK-DEMO.bat to test block/pass behavior.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
