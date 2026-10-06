"""Show or reset the REAL admin account (live workspace, never listed in the Demo Center).

    python tools/admin_account.py          # create it if missing and print where the password is
    python tools/admin_account.py --reset  # generate a new password (signs nothing else out)

To choose your own email/password instead, set PRIVPASS_ADMIN_EMAIL and PRIVPASS_ADMIN_PASSWORD in .env
and restart the app.
"""
from __future__ import annotations
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.db import init_db  # noqa: E402
from app.bootstrap import ADMIN_FILE, ensure_real_admin  # noqa: E402


def main() -> None:
    init_db()
    email, password = ensure_real_admin(reset="--reset" in sys.argv)
    print(f"Real admin email: {email}")
    if password:
        print(f"New password:     {password}")
    elif ADMIN_FILE.exists():
        print(f"Password: see {ADMIN_FILE}")
    else:
        print("Password: the one set in .env (PRIVPASS_ADMIN_PASSWORD) or the one you changed it to. Use --reset for a new one.")


if __name__ == "__main__":
    main()
