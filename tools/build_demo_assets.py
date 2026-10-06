"""Rebuild the demo ZIPs in demo-assets/ from data/.

* PrivPass-Demo-Leak-Repo.zip     - working-tree secrets + risky code (data/demo-repo)
* PrivPass-Clean-Demo-Repo.zip    - should PASS the gate (data/clean-demo-repo)
* PrivPass-History-Leak-Repo.zip  - a real git repo whose HEAD is clean, but whose history still
                                    contains a Stripe key and a GitHub token that a developer
                                    "fixed" by deleting the lines. Teaches: rotate, don't just delete.
All credential-looking values are fake and non-functional.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "demo-assets"


def zip_dir(src: Path, dest: Path, arc_root: str = "") -> None:
    with zipfile.ZipFile(dest, "w", zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(src.rglob("*")):
            if path.is_file():
                zf.write(path, str(Path(arc_root) / path.relative_to(src)).replace("\\", "/"))


def git(repo: Path, *args: str, date: str | None = None) -> None:
    env = {**os.environ, "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull}
    if date:
        env.update(GIT_AUTHOR_DATE=date, GIT_COMMITTER_DATE=date)
    subprocess.run(["git", "-C", str(repo), *args], check=True, env=env, stdout=subprocess.DEVNULL)


def build_history_repo(dest: Path) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        repo = Path(tmp) / "payments-service"
        repo.mkdir()
        git(repo, "init", "-q", "-b", "main")
        git(repo, "config", "user.name", "Riya Dev")
        git(repo, "config", "user.email", "riya.dev@payments.example")
        (repo / "README.md").write_text("# payments-service\n\nDEMO-ONLY repository for PrivPass SecretGuard history scanning.\n", encoding="utf-8")
        (repo / "billing.py").write_text(
            "# DEMO-ONLY: fake, non-functional credentials.\n"
            "import stripe\n\n"
            'stripe.api_key = "sk_test_4eC39HqLyjWDarjtT1zdp7dcDEMO"\n'  # secretguard:allow (fake demo value)
            'GITHUB_DEPLOY_TOKEN = "ghp_DemoHistoryOnly0123456789abcdefABCD"\n\n'  # secretguard:allow (fake demo value)
            "def charge(amount):\n    return stripe.Charge.create(amount=amount, currency='usd')\n",
            encoding="utf-8")
        git(repo, "add", "-A"); git(repo, "commit", "-q", "-m", "Add Stripe billing", date="2026-03-02T10:15:00+05:30")
        (repo / "invoices.py").write_text("def total(items):\n    return sum(i['amount'] for i in items)\n", encoding="utf-8")
        git(repo, "add", "-A"); git(repo, "commit", "-q", "-m", "Add invoice totals", date="2026-03-04T16:40:00+05:30")
        (repo / "billing.py").write_text(
            "import os\n\nimport stripe\n\n"
            'stripe.api_key = os.environ["STRIPE_API_KEY"]\n'
            'GITHUB_DEPLOY_TOKEN = os.environ.get("GITHUB_DEPLOY_TOKEN", "")\n\n'
            "def charge(amount):\n    return stripe.Charge.create(amount=amount, currency='usd')\n",
            encoding="utf-8")
        git(repo, "add", "-A"); git(repo, "commit", "-q", "-m", "Remove hardcoded keys (oops)", date="2026-03-05T09:05:00+05:30")
        zip_dir(repo, dest, "payments-service")


def main() -> None:
    OUT.mkdir(exist_ok=True)
    zip_dir(ROOT / "data" / "demo-repo", OUT / "PrivPass-Demo-Leak-Repo.zip")
    zip_dir(ROOT / "data" / "clean-demo-repo", OUT / "PrivPass-Clean-Demo-Repo.zip")
    if shutil.which("git"):
        build_history_repo(OUT / "PrivPass-History-Leak-Repo.zip")
    for name in sorted(p.name for p in OUT.glob("*.zip")):
        print("built", name)


if __name__ == "__main__":
    main()
