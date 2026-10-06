# DEMO-ONLY: intentionally unsafe code patterns for the SecretGuard "Secure Code Checker" rules.
# Never copy these into real code - each line shows the safer alternative in the scanner output.
import sqlite3
import subprocess

import requests
import yaml


def ping(host: str):
    return subprocess.run(f"ping -c1 {host}", shell=True)


def fetch_invoice(url: str):
    return requests.get(url, verify=False)


def find_user(db: sqlite3.Connection, name: str):
    return db.execute(f"SELECT * FROM users WHERE name = '{name}'")


def load_settings(raw: str):
    return yaml.load(raw)
