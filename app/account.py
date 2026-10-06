"""Account security: breach re-check at login, password change (with client-side vault
re-encryption) and passkeys (WebAuthn)."""
from __future__ import annotations

import hmac
import json
import secrets
from datetime import datetime, timezone
from ipaddress import ip_address
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from .db import db
from .models import Passkey, PasswordEvent, Session as DbSession, User, VaultItem
from .notify import notify
from .security import b64d, b64e, decrypt_verifier, encrypt_verifier, hmac_hex, uid, verifier_integrity

router = APIRouter(prefix="/api/auth")


def _main():
    from . import main
    return main


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


# ------------------------------------------------------------------ breach re-check after login
class RecheckBody(BaseModel):
    status: str  # "breached" | "safe" | "unavailable"
    count: int = Field(default=0, ge=0)


@router.post("/breach-recheck")
def breach_recheck(request: Request, session: Session = Depends(db)):
    """'Check my password now': the SERVER re-checks the stored breach-watch value against HIBP.
    Nothing is taken from the browser, so the result can't be faked. A match locks the account."""
    m = _main()
    user, _ = m.get_current_session(request, session); m.require_same_origin(request); m.rate_limited(request, "recheck", 10, 60)
    res = m.run_breach_check(session, user, fresh=True)
    session.add(PasswordEvent(id=uid(), user_id=user.id, event_type="login_recheck", breached=res.status == "breached", score=0, score_label=res.status, guess_log10=0))
    session.commit()
    if user.breach_locked:
        raise HTTPException(423, m.locked_detail(user))
    return {"status": res.status, "checked_at": user.breach_checked_at.isoformat() if user.breach_checked_at else None}


# ------------------------------------------------------------------ password change
class ChangeChallengeBody(BaseModel):
    pass


@router.post("/change-password/challenge")
def change_challenge(request: Request, session: Session = Depends(db)):
    m = _main()
    user, _ = m.get_current_session(request, session); m.require_same_origin(request)
    if user.workspace == "demo":
        raise HTTPException(403, "Demo accounts are shared by everyone trying the app, so their password cannot be changed. Create your own account to try this.")
    nonce = m.issue_token(session, "pwchange_challenge", 180, user_id=user.id)
    session.commit()
    return {"nonce": nonce, "salt_b64": user.salt_b64, "watch_salt_b64": user.watch_salt_b64, "kdf": user.kdf_version or 1,
            "vault_salt_b64": user.vault_salt_b64, "vault_check_ciphertext": user.vault_check_ciphertext}


class ReencryptedItem(BaseModel):
    id: str
    ciphertext_b64: str = Field(min_length=40, max_length=200000)


class ChangePasswordBody(BaseModel):
    nonce: str
    proof: str                     # HMAC(old verifier, nonce): proves knowledge of the current password
    salt_b64: str                  # new credential material (see app/breachwatch.py)
    watch_salt_b64: str
    prefix: str = Field(min_length=5, max_length=5)
    watch_b64: str
    verifier_b64: str = ""         # ignored since 7.3
    score: int = Field(ge=0, le=100)
    score_label: str
    breached: bool = False
    breach_gate: dict
    vault_salt_b64: str
    vault_check_ciphertext: Optional[str] = None
    items: list[ReencryptedItem] = []


@router.post("/change-password")
def change_password(body: ChangePasswordBody, request: Request, response: Response, session: Session = Depends(db)):
    m = _main()
    user, current = m.get_current_session(request, session); m.require_same_origin(request); m.rate_limited(request, "pwchange", 10, 300)
    if user.workspace == "demo":
        raise HTTPException(403, "Demo accounts are shared by everyone trying the app, so their password cannot be changed. Create your own account to try this.")
    if not m.consume_token(session, "pwchange_challenge", body.nonce, user_id=user.id):
        session.commit(); raise HTTPException(401, "challenge expired - try again")
    old = decrypt_verifier(user.verifier_ciphertext).decode()
    if not hmac.compare_digest(hmac_hex(b64d(old), body.nonce), body.proof):
        m.audit(session, user.id, "PASSWORD_CHANGE_FAILED", severity="WARN"); session.commit()
        raise HTTPException(401, "current password is incorrect")
    gate = m.BreachGateEvidence(**body.breach_gate)
    if not m.consume_token(session, "breach_gate_change", gate.ticket):
        raise HTTPException(400, "breach check ticket missing, expired or already used")
    m._policy_gate(gate, body.breached)
    material = m._material(body)
    m._server_breach_check(*material, gate)
    if len(b64d(body.vault_salt_b64)) != 16:
        raise HTTPException(400, "invalid vault salt")
    # Every vault item must be re-encrypted in the same request, or none - never lose data.
    existing = {v.id: v for v in session.scalars(select(VaultItem).where(VaultItem.owner_user_id == user.id))}
    if set(existing) != {i.id for i in body.items}:
        raise HTTPException(409, "vault changed during re-encryption - reload and try again")
    for item in body.items:
        existing[item.id].ciphertext_b64 = item.ciphertext_b64
        existing[item.id].version += 1
        existing[item.id].updated_at = _now()
    from .breachwatch import install
    install(user, *material)
    user.breach_checked_at = _now(); user.breach_check_status = "safe"
    user.vault_salt_b64 = body.vault_salt_b64
    user.vault_check_ciphertext = body.vault_check_ciphertext
    user.must_change_password = False
    user.breach_flag_source = None
    user.password_changed_at = _now()
    # Sign out every other session; keep this one.
    session.query(DbSession).filter(DbSession.user_id == user.id, DbSession.id != current.id, DbSession.revoked_at.is_(None)).update({DbSession.revoked_at: _now()})
    session.add(PasswordEvent(id=uid(), user_id=user.id, event_type="change", breached=False, score=body.score, score_label=body.score_label, guess_log10=0))
    m.audit(session, user.id, "PASSWORD_CHANGED", meta={"vault_items_reencrypted": len(body.items)})
    notify(session, "account", "Password changed", f"{len(body.items)} vault item(s) were re-encrypted in your browser. Other sessions were signed out.", "INFO", "account", user_id=user.id)
    session.commit()
    return {"ok": True, "reencrypted": len(body.items)}


# ------------------------------------------------------------------ passkeys (WebAuthn)
def _rp(request: Request) -> tuple[str, str]:
    host = request.url.hostname or "localhost"
    try:
        ip_address(host)
        raise HTTPException(400, f"Passkeys need a domain name. Open http://localhost:{request.url.port or 80} instead of the IP address.")
    except ValueError:
        pass
    origin = request.headers.get("origin") or f"{request.url.scheme}://{request.headers.get('host')}"
    return host, origin


def _wa():
    try:
        import webauthn
        from webauthn.helpers import structs
        return webauthn, structs
    except Exception:
        raise HTTPException(501, "passkeys unavailable: install the 'webauthn' package")


@router.post("/passkeys/register/begin")
def passkey_register_begin(request: Request, session: Session = Depends(db)):
    m = _main(); wa, st = _wa()
    user, _ = m.get_current_session(request, session); m.require_same_origin(request)
    rp_id, _origin = _rp(request)
    existing = session.scalars(select(Passkey).where(Passkey.user_id == user.id)).all()
    opts = wa.generate_registration_options(
        rp_id=rp_id, rp_name="PrivPass Shield", user_id=user.id.encode(), user_name=user.email, user_display_name=user.email,
        exclude_credentials=[st.PublicKeyCredentialDescriptor(id=b64d(p.credential_id)) for p in existing],
        authenticator_selection=st.AuthenticatorSelectionCriteria(resident_key=st.ResidentKeyRequirement.REQUIRED,
                                                                  user_verification=st.UserVerificationRequirement.PREFERRED))
    m.issue_token(session, "webauthn_reg", 300, user_id=user.id, raw=b64e(opts.challenge))
    session.commit()
    return json.loads(wa.options_to_json(opts))


class PasskeyFinishBody(BaseModel):
    credential: dict
    name: str = Field(default="Passkey", max_length=80)


@router.post("/passkeys/register/finish")
def passkey_register_finish(body: PasskeyFinishBody, request: Request, session: Session = Depends(db)):
    m = _main(); wa, _st = _wa()
    user, _ = m.get_current_session(request, session); m.require_same_origin(request)
    rp_id, origin = _rp(request)
    client_data = json.loads(b64d(body.credential.get("response", {}).get("clientDataJSON", "")) or b"{}")
    challenge = client_data.get("challenge", "")
    if not m.consume_token(session, "webauthn_reg", challenge, user_id=user.id):
        raise HTTPException(400, "registration challenge expired")
    try:
        v = wa.verify_registration_response(credential=body.credential, expected_challenge=b64d(challenge), expected_origin=origin, expected_rp_id=rp_id)
    except Exception as exc:
        raise HTTPException(400, f"passkey registration failed: {exc}")
    pk = Passkey(id=uid(), user_id=user.id, credential_id=b64e(v.credential_id), public_key=b64e(v.credential_public_key), sign_count=v.sign_count,
                 name=body.name or "Passkey", transports=json.dumps(body.credential.get("response", {}).get("transports", [])))
    session.add(pk)
    m.audit(session, user.id, "PASSKEY_ADDED", meta={"name": pk.name})
    notify(session, "account", "Passkey added", f"“{pk.name}” can now sign you in without a password.", "INFO", "account", user_id=user.id)
    session.commit()
    return {"ok": True, "id": pk.id, "name": pk.name}


@router.get("/passkeys")
def passkey_list(request: Request, session: Session = Depends(db)):
    m = _main()
    user, _ = m.get_current_session(request, session)
    return [{"id": p.id, "name": p.name, "created_at": p.created_at.isoformat(), "last_used_at": p.last_used_at.isoformat() if p.last_used_at else None}
            for p in session.scalars(select(Passkey).where(Passkey.user_id == user.id))]


@router.delete("/passkeys/{pk_id}")
def passkey_delete(pk_id: str, request: Request, session: Session = Depends(db)):
    m = _main()
    user, _ = m.get_current_session(request, session); m.require_same_origin(request)
    pk = session.get(Passkey, pk_id)
    if not pk or pk.user_id != user.id:
        raise HTTPException(404, "passkey not found")
    session.delete(pk); m.audit(session, user.id, "PASSKEY_REMOVED"); session.commit()
    return {"ok": True}


@router.post("/passkeys/login/begin")
def passkey_login_begin(request: Request, session: Session = Depends(db)):
    m = _main(); wa, st = _wa()
    m.rate_limited(request, "passkey", 30, 60); m.require_same_origin(request)
    rp_id, _origin = _rp(request)
    opts = wa.generate_authentication_options(rp_id=rp_id, user_verification=st.UserVerificationRequirement.PREFERRED)
    m.issue_token(session, "webauthn_auth", 300, raw=b64e(opts.challenge))
    session.commit()
    return json.loads(wa.options_to_json(opts))


class PasskeyLoginBody(BaseModel):
    credential: dict


@router.post("/passkeys/login/finish")
def passkey_login_finish(body: PasskeyLoginBody, request: Request, response: Response, session: Session = Depends(db)):
    m = _main(); wa, _st = _wa()
    m.rate_limited(request, "passkey", 30, 60); m.require_same_origin(request)
    rp_id, origin = _rp(request)
    client_data = json.loads(b64d(body.credential.get("response", {}).get("clientDataJSON", "")) or b"{}")
    challenge = client_data.get("challenge", "")
    if not m.consume_token(session, "webauthn_auth", challenge):
        session.commit(); raise HTTPException(401, "passkey challenge expired")
    pk = session.scalar(select(Passkey).where(Passkey.credential_id == body.credential.get("rawId", body.credential.get("id", ""))))
    user = session.get(User, pk.user_id) if pk else None
    if not pk or not user or not user.is_active:
        session.commit(); raise HTTPException(401, "unknown passkey")
    if user.breach_locked:        # a breached password locks the whole account, passkeys included, until reset
        session.commit(); raise HTTPException(423, m.locked_detail(user))
    from .db import current_workspace
    current_workspace.set(user.workspace)
    try:
        v = wa.verify_authentication_response(credential=body.credential, expected_challenge=b64d(challenge), expected_rp_id=rp_id, expected_origin=origin,
                                              credential_public_key=b64d(pk.public_key), credential_current_sign_count=pk.sign_count)
    except Exception as exc:
        m.record_login(session, request, user.email, True, False, "passkey_failed"); session.commit()
        raise HTTPException(401, f"passkey verification failed: {exc}")
    pk.sign_count = v.new_sign_count; pk.last_used_at = _now()
    m.record_login(session, request, user.email, True, True, "passkey")
    return m.start_session(session, response, user, "passkey")
