"""
Two-factor helpers — TOTP pairing and code verification.

Security properties implemented here:

  1. Secrets encrypted at rest.
     TOTP secrets are the crown jewels: anyone holding one can mint valid
     codes forever. When ENCRYPTION_KEY is set they are stored Fernet-
     encrypted with an 'enc:v1:' prefix. Rows written before the key existed
     stay readable, and startup_db() migrates them opportunistically.

  2. Replay protection.
     A TOTP code stays valid for its whole ~30s step, so without this a code
     observed once (shoulder-surf, screen share, leaked log) could be spent
     on several sensitive commands. Each successful verification records the
     time-step it consumed; that step and everything before it are refused.
     A replayed code is simply reported as invalid to the caller.

  3. No self-service recovery.
     TOTP is the only credential. Single-use backup codes were removed
     deliberately — see the "Account recovery" note further down. Losing an
     authenticator requires an owner to run /reset-user, which is logged.

Set ENCRYPTION_KEY in .env. Generate one with:
    python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"

Without it the bot still runs (and warns), but secrets are stored in plaintext.
"""

import base64
import hashlib
import io
import os
import time

import discord
import pyotp
import pyqrcode
from cryptography.fernet import Fernet, InvalidToken

import db_handler


ENC_PREFIX = "enc:v1:"

_TOTP_STEP_SECONDS = 30

_key_missing_warned = False


# ---------------------------------------------------------------------------
# Key management
# ---------------------------------------------------------------------------

def _raw_key() -> str:
    return os.getenv("ENCRYPTION_KEY", "").strip()


def _fernet():
    """
    Return a Fernet instance, or None when no ENCRYPTION_KEY is configured.

    Accepts either a real Fernet key or an arbitrary passphrase (hashed into
    a valid key), so a mis-formatted key degrades to 'still encrypted' rather
    than 'silently plaintext'.
    """
    global _key_missing_warned
    raw = _raw_key()
    if not raw:
        if not _key_missing_warned:
            print(
                "[2FA] WARNING: ENCRYPTION_KEY is not set — TOTP secrets and backup "
                "codes are stored unencrypted. Anyone who can read database.db can "
                "bypass 2FA for every privileged user. See two_factor_helper.py."
            )
            _key_missing_warned = True
        return None
    try:
        return Fernet(raw.encode())
    except Exception:
        digest = hashlib.sha256(raw.encode()).digest()
        return Fernet(base64.urlsafe_b64encode(digest))


def encryption_enabled() -> bool:
    return bool(_raw_key())


# ---------------------------------------------------------------------------
# Secret encryption
# ---------------------------------------------------------------------------

def encrypt_secret(plain: str) -> str:
    """Encrypt a TOTP secret for storage. Returns plaintext if no key is set."""
    f = _fernet()
    if f is None:
        return plain
    return ENC_PREFIX + f.encrypt(plain.encode()).decode()


def decrypt_secret(stored: str):
    """
    Decrypt a stored TOTP secret.

    Rows written before encryption was enabled have no prefix and are returned
    as-is. Returns None if a value is encrypted but cannot be decrypted (wrong
    or rotated key) so callers fail closed rather than verifying against junk.
    """
    if stored is None:
        return None
    if not stored.startswith(ENC_PREFIX):
        return stored
    f = _fernet()
    if f is None:
        print("[2FA] ERROR: encrypted secret found but ENCRYPTION_KEY is not set.")
        return None
    try:
        return f.decrypt(stored[len(ENC_PREFIX):].encode()).decode()
    except InvalidToken:
        print("[2FA] ERROR: could not decrypt a stored secret — has ENCRYPTION_KEY changed?")
        return None


def migrate_plaintext_secrets(conn) -> int:
    """
    Encrypt any secrets still stored in plaintext. Idempotent and safe to run
    on every startup. Returns the number of rows upgraded.
    """
    if not encryption_enabled():
        return 0
    try:
        rows = conn.execute("SELECT user_id, secret FROM users").fetchall()
    except Exception as e:
        print(f"[2FA] Secret migration skipped: {e}")
        return 0

    upgraded = 0
    for user_id, secret in rows:
        if secret is None or secret.startswith(ENC_PREFIX):
            continue
        try:
            conn.execute(
                "UPDATE users SET secret=? WHERE user_id=?",
                (encrypt_secret(secret), user_id),
            )
            upgraded += 1
        except Exception as e:
            print(f"[2FA] Failed to encrypt secret for {user_id}: {e}")
    if upgraded:
        conn.commit()
        print(f"[2FA] Encrypted {upgraded} previously-plaintext TOTP secret(s).")
    return upgraded


# ---------------------------------------------------------------------------
# TOTP setup
# ---------------------------------------------------------------------------

def setup_and_get_path(ctx, connection):
    """
    Generate a TOTP secret, render its QR code, and store the (encrypted)
    secret. Returns (qr_buffer, secret).

    The QR encodes the secret, so it is rendered to an in-memory buffer and
    never touches disk — previously it was written to ./data and relied on a
    once-a-minute cleanup task, leaving a window where the secret sat in a
    world-readable file.
    """
    secret = pyotp.random_base32()
    user_id = int(ctx.user.id)
    uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name=f"{ctx.user} ({user_id})",
        issuer_name="Discord-Shield",
    )
    qr = pyqrcode.create(uri, error='L')
    buffer = io.BytesIO()
    qr.png(buffer, scale=6)
    buffer.seek(0)

    db_handler.insert_user(conn=connection, info=(user_id, encrypt_secret(secret), 0))
    return buffer, secret


# ---------------------------------------------------------------------------
# TOTP verification
# ---------------------------------------------------------------------------

def _current_step() -> int:
    return int(time.time()) // _TOTP_STEP_SECONDS


def verify_code(connection, user_id: int, code) -> bool:
    """
    Verify a 6-digit TOTP code. Accepts int or str, zero-pads to 6 digits.

    Returns False for an incorrect code AND for a correct code that has
    already been spent this time-step (replay). Callers surface both the same
    way; a replayed code is not a legitimate authentication.
    """
    try:
        code_str = f"{int(code):06d}"
    except (TypeError, ValueError):
        return False

    stored = db_handler.get_secret(conn=connection, user_id=user_id)
    secret = decrypt_secret(stored)
    if not secret:
        return False

    step = _current_step()
    last_step = db_handler.get_last_totp_step(connection, user_id)
    if last_step is not None and last_step >= step:
        # This step (or a later one) was already consumed — refuse the replay.
        return False

    try:
        ok = pyotp.TOTP(secret).verify(code_str)
    except Exception:
        return False

    if ok:
        db_handler.set_last_totp_step(connection, user_id, step)
    return bool(ok)


def get_log_channel(bot, guild: discord.Guild):
    """Return the log channel object for a guild, or None."""
    log_id = db_handler.get_log_channel(bot.CONN, guild.id)
    return bot.get_channel(log_id) if log_id else None


# ---------------------------------------------------------------------------
# Account recovery
# ---------------------------------------------------------------------------
#
# There is deliberately NO self-service recovery here.
#
# Single-use backup codes were removed. They looked like a safety net but
# functioned as a second, weaker credential: shown once in a Discord message,
# they were routinely screenshotted into saved messages or a notes app. That
# turned "attacker phishes a Discord account" into "attacker phishes a Discord
# account AND finds the codes sitting in it" — at which point they could wipe
# the victim's 2FA over DM, re-pair their own authenticator, and inherit the
# keycard with no human ever noticing.
#
# Losing an authenticator is now handled the way losing a building pass is:
# a person with authority re-issues it. An owner runs /reset-user, which clears
# the account and is written to the audit log, and the user re-enrols with
# /create-2fa.
#
# The global operator (MASTER_USER_ID) is the one account no one can reset in
# band. Its recovery is deliberately out of band, via the infrastructure it
# already controls — see "Operator lockout" in the README.
