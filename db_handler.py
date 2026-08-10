import sqlite3
import time
from sqlite3 import Error


# ---------------------------------------------------------------------------
# Read cache
#
# on_message previously issued up to ~8 synchronous SQLite queries per message
# (guild check, filter flag, four exemption lookups, whitelist fetch). sqlite3
# blocks the event loop, so on a busy guild that stalls every other listener.
#
# These are read-mostly config values, so they are cached briefly and evicted
# explicitly whenever the guild's config is written. Keys include the
# connection identity so separate databases (e.g. per-test in-memory ones)
# never share entries.
# ---------------------------------------------------------------------------

_CACHE: dict = {}
_CACHE_TTL = 10.0
_MISS = object()


def _ckey(conn, name: str, guild_id: int):
    return (id(conn), name, guild_id)


def _cache_get(key):
    entry = _CACHE.get(key)
    if entry is None:
        return _MISS
    value, expires = entry
    if time.monotonic() > expires:
        _CACHE.pop(key, None)
        return _MISS
    return value


def _cache_put(key, value):
    _CACHE[key] = (value, time.monotonic() + _CACHE_TTL)
    return value


def invalidate_guild(conn, guild_id: int):
    """Drop every cached value for one guild. Call after any config write."""
    for key in [k for k in _CACHE if k[0] == id(conn) and k[2] == guild_id]:
        _CACHE.pop(key, None)


def clear_cache():
    """Drop the entire cache (used by tests)."""
    _CACHE.clear()


# ---------------------------------------------------------------------------
# Connection
# ---------------------------------------------------------------------------

def create_connection(db_file: str):
    try:
        conn = sqlite3.connect(
            db_file,
            detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES
        )
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn
    except Error as e:
        print(f"[DB] Connection error: {e}")
        return None


def _exec(conn, sql: str, params=()):
    cur = conn.cursor()
    cur.execute(sql, params)
    conn.commit()
    return cur


# The full schema, as a module-level constant so tests build their in-memory
# database from THIS list rather than a hand-copied duplicate. The copy in
# tests/conftest.py silently drifted out of date every time a table was added,
# producing failures that looked like product bugs but were fixture rot.
SCHEMA = [
        # 2FA users
        # last_totp_step: the TOTP time-step most recently consumed by a
        # successful verification. Codes from that step or earlier are refused,
        # which stops an observed code being replayed within its 30s window.
        """CREATE TABLE IF NOT EXISTS users (
            user_id        INTEGER PRIMARY KEY,
            secret         TEXT    NOT NULL,
            verified       INTEGER NOT NULL CHECK (verified IN (0, 1)),
            last_totp_step INTEGER
        )""",

        # Guild configuration
        """CREATE TABLE IF NOT EXISTS guilds (
            guild_id             INTEGER PRIMARY KEY,
            event_channel        INTEGER,
            announcement_channel INTEGER,
            log_channel          INTEGER,
            webhook_protection   INTEGER NOT NULL DEFAULT 1 CHECK (webhook_protection IN (0, 1)),
            verified_bots        INTEGER NOT NULL DEFAULT 0 CHECK (verified_bots IN (0, 1)),
            link_filter_enabled  INTEGER NOT NULL DEFAULT 0 CHECK (link_filter_enabled IN (0, 1)),
            panic_active         INTEGER NOT NULL DEFAULT 0 CHECK (panic_active IN (0, 1)),
            announce_timeout     INTEGER NOT NULL DEFAULT 300,
            -- 'flag' | 'ban' | 'kick' | 'timeout:<hours>'
            -- Defaults to 'flag' (log only): a fresh server has untested
            -- patterns, and an auto-ban on a false positive cannot be undone
            -- in bulk. _run_migrations adds this column to older databases.
            name_filter_action   TEXT DEFAULT 'flag'
        )""",

        # Announcers (trusted_members)
        """CREATE TABLE IF NOT EXISTS trusted_members (
            trusted_id INTEGER PRIMARY KEY AUTOINCREMENT,
            guild_id   INTEGER NOT NULL,
            member_id  INTEGER NOT NULL,
            UNIQUE (guild_id, member_id),
            FOREIGN KEY (guild_id) REFERENCES guilds(guild_id) ON DELETE CASCADE
        )""",

        # Announcement channels
        """CREATE TABLE IF NOT EXISTS channel_table (
            channel_id INTEGER PRIMARY KEY,
            guild_id   INTEGER NOT NULL,
            FOREIGN KEY (guild_id) REFERENCES guilds(guild_id) ON DELETE CASCADE
        )""",

        # Active announcement permission grants (kept for backward compat)
        """CREATE TABLE IF NOT EXISTS active_announcements (
            announcement_id INTEGER PRIMARY KEY AUTOINCREMENT,
            member_id       INTEGER NOT NULL,
            channel_id      INTEGER NOT NULL,
            timestamp       DATETIME DEFAULT CURRENT_TIMESTAMP,
            UNIQUE (member_id, channel_id),
            FOREIGN KEY (member_id) REFERENCES users(user_id) ON DELETE CASCADE
        )""",

        # Link whitelist (allowed domains / exact URLs)
        """CREATE TABLE IF NOT EXISTS link_whitelist (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            guild_id INTEGER NOT NULL,
            type     TEXT    NOT NULL CHECK (type IN ('domain', 'specific')),
            url      TEXT    NOT NULL,
            added_by INTEGER,
            UNIQUE (guild_id, type, url)
        )""",

        # Safe roles (allowed for /role and /bulk-role)
        """CREATE TABLE IF NOT EXISTS safe_roles (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            guild_id INTEGER NOT NULL,
            role_id  INTEGER NOT NULL,
            UNIQUE (guild_id, role_id)
        )""",

        # NOTE: the backup_codes table was removed deliberately. Single-use
        # recovery codes were a second credential that users saved insecurely,
        # letting a phished Discord account be escalated into a full bot
        # takeover with no human in the loop. Recovery is now /reset-user by an
        # owner. _run_migrations drops the table on existing installs.

        # Link managers (can manage link whitelist, cannot toggle filter)
        """CREATE TABLE IF NOT EXISTS link_managers (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            guild_id  INTEGER NOT NULL,
            member_id INTEGER NOT NULL,
            UNIQUE (guild_id, member_id)
        )""",

        # Panic backups
        """CREATE TABLE IF NOT EXISTS panic_role_backup (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            guild_id    INTEGER NOT NULL,
            role_id     INTEGER NOT NULL,
            perms_value INTEGER NOT NULL,
            timestamp   DATETIME DEFAULT CURRENT_TIMESTAMP
        )""",
        """CREATE TABLE IF NOT EXISTS panic_channel_backup (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            guild_id    INTEGER NOT NULL,
            channel_id  INTEGER NOT NULL,
            allow_value INTEGER NOT NULL,
            deny_value  INTEGER NOT NULL,
            timestamp   DATETIME DEFAULT CURRENT_TIMESTAMP
        )""",

        # Entities exempt from link filter (channels, roles, users, categories)
        """CREATE TABLE IF NOT EXISTS link_filter_whitelist (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            guild_id    INTEGER NOT NULL,
            entity_type TEXT    NOT NULL CHECK (entity_type IN ('channel', 'role', 'user', 'category')),
            entity_id   INTEGER NOT NULL,
            added_by    INTEGER,
            UNIQUE (guild_id, entity_type, entity_id)
        )""",

        # Temporary webhook protection bypass (30 min window)
        """CREATE TABLE IF NOT EXISTS webhook_temp_disable (
            guild_id    INTEGER PRIMARY KEY,
            disabled_by INTEGER NOT NULL,
            expires_at  DATETIME NOT NULL
        )""",

        # Bot-sent embeds (tracked for edit/delete/list)
        """CREATE TABLE IF NOT EXISTS embeds (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            guild_id    INTEGER NOT NULL,
            channel_id  INTEGER NOT NULL,
            message_id  INTEGER NOT NULL UNIQUE,
            author_id   INTEGER NOT NULL,
            title       TEXT,
            description TEXT,
            color       INTEGER NOT NULL DEFAULT 16741142,
            footer      TEXT,
            image_url   TEXT,
            created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (guild_id) REFERENCES guilds(guild_id) ON DELETE CASCADE
        )""",

        # Member verification (captcha gate before a member gets the verified role)
        # log_channel_id: optional dedicated destination for join/verification
        # events. NULL means "use the guild's main log channel".
        """CREATE TABLE IF NOT EXISTS verification_config (
            guild_id         INTEGER PRIMARY KEY,
            channel_id       INTEGER NOT NULL,
            role_id          INTEGER NOT NULL,
            panel_message_id INTEGER,
            enabled          INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
            min_account_age  INTEGER NOT NULL DEFAULT 0,
            log_channel_id   INTEGER,
            created_at       DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (guild_id) REFERENCES guilds(guild_id) ON DELETE CASCADE
        )""",

        # Per-guild embed branding (colour / footer shown on bot embeds)
        """CREATE TABLE IF NOT EXISTS guild_branding (
            guild_id INTEGER PRIMARY KEY,
            color    INTEGER,
            footer   TEXT,
            icon_url TEXT,
            FOREIGN KEY (guild_id) REFERENCES guilds(guild_id) ON DELETE CASCADE
        )""",

        # Name filters (phrase and regex patterns checked on join / name change)
        """CREATE TABLE IF NOT EXISTS name_filters (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            guild_id   INTEGER NOT NULL,
            type       TEXT    NOT NULL CHECK(type IN ('phrase', 'regex')),
            pattern    TEXT    NOT NULL,
            added_by   INTEGER,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            UNIQUE (guild_id, type, pattern),
            FOREIGN KEY (guild_id) REFERENCES guilds(guild_id) ON DELETE CASCADE
        )""",
]


def create_schema(conn):
    """Create every table if missing. Safe to run on an existing database."""
    for sql in SCHEMA:
        try:
            conn.execute(sql)
        except Error as e:
            print(f"[DB] Table creation error: {e}")
    conn.commit()


def startup_db():
    import os
    db_path = os.getenv("DATABASE_PATH", "database.db")
    os.makedirs(os.path.dirname(db_path), exist_ok=True) if os.path.dirname(db_path) else None
    conn = create_connection(db_path)
    if conn is None:
        return None

    # Say plainly where the data is actually going. On container hosts a volume
    # can be mounted correctly while DATABASE_PATH still points at ephemeral
    # disk — the setup looks healthy and silently resets on every deploy. The
    # absolute path in the logs makes that visible in one glance.
    resolved = os.path.abspath(db_path)
    existed = os.path.getsize(resolved) > 0 if os.path.exists(resolved) else False
    print(f"[DB] Using database: {resolved}")
    if not os.getenv("DATABASE_PATH"):
        print("[DB] WARNING: DATABASE_PATH is not set, so the database lives in the "
              "working directory. On Railway/Docker that is wiped on every deploy — "
              "point DATABASE_PATH at a mounted volume.")
    elif not existed:
        print("[DB] NOTE: this database is new/empty. If you expected existing data, "
              "check that DATABASE_PATH matches your volume's mount path.")

    create_schema(conn)

    # Migrations for existing databases
    _run_migrations(conn)

    conn.commit()
    return conn


def _run_migrations(conn):
    """Apply ALTER TABLE migrations for existing installs."""
    migrations = [
        # Add announce_timeout column to guilds if missing
        "ALTER TABLE guilds ADD COLUMN announce_timeout INTEGER NOT NULL DEFAULT 300",
        # Add name_filter_action column to guilds (default: ban)
        "ALTER TABLE guilds ADD COLUMN name_filter_action TEXT DEFAULT 'ban'",
        # TOTP replay protection — records the last consumed 30s time-step
        "ALTER TABLE users ADD COLUMN last_totp_step INTEGER",
        # Announcement grants must survive a restart so they can still be revoked
        "ALTER TABLE active_announcements ADD COLUMN guild_id INTEGER",
        "ALTER TABLE active_announcements ADD COLUMN expires_at INTEGER",
        # Optional separate destination for join/verification events
        "ALTER TABLE verification_config ADD COLUMN log_channel_id INTEGER",
        # Ensure webhook_protection defaults to 1 (we can't change defaults via ALTER, just document)
    ]
    for sql in migrations:
        try:
            conn.execute(sql)
            conn.commit()
        except sqlite3.OperationalError:
            pass  # Column already exists, skip

    # Drop the retired backup_codes table.
    #
    # Left in place these rows are stale credential material: if the feature
    # were ever re-enabled, codes issued years earlier — and long since
    # screenshotted into someone's notes app — would start working again.
    # Dead credentials should not linger in the database.
    try:
        conn.execute("DROP TABLE IF EXISTS backup_codes")
        conn.commit()
    except Exception as e:
        print(f"[DB] Could not drop retired backup_codes table: {e}")

    # Correct stale announce_timeout value: the old default was 120s; bump to 300s
    # for any guild that still has the old default and hasn't manually changed it.
    try:
        conn.execute("UPDATE guilds SET announce_timeout = 300 WHERE announce_timeout = 120")
        conn.commit()
    except Exception as e:
        print(f"[DB] announce_timeout default correction skipped: {e}")

    # Remove the erroneous FK on trusted_members.member_id → users.user_id.
    # Members must be addable before they have run /create-2fa.
    # SQLite can't DROP CONSTRAINT, so we recreate the table without it.
    #
    # GUARDED: this used to run on EVERY startup, copying and re-creating the
    # table each boot even when the bad constraint was long gone. That is
    # pointless work and a standing risk — the script drops the live table
    # before renaming the copy into place, so a crash or container kill at the
    # wrong moment would take the announcer list with it. Now we look first and
    # only rebuild when the offending foreign key is actually present.
    if not _trusted_members_needs_rebuild(conn):
        return

    print("[DB] Rebuilding trusted_members to drop a legacy foreign key…")
    try:
        conn.executescript("""
            PRAGMA foreign_keys=OFF;

            CREATE TABLE IF NOT EXISTS trusted_members_new (
                trusted_id INTEGER PRIMARY KEY AUTOINCREMENT,
                guild_id   INTEGER NOT NULL,
                member_id  INTEGER NOT NULL,
                UNIQUE (guild_id, member_id),
                FOREIGN KEY (guild_id) REFERENCES guilds(guild_id) ON DELETE CASCADE
            );

            INSERT OR IGNORE INTO trusted_members_new (trusted_id, guild_id, member_id)
                SELECT trusted_id, guild_id, member_id FROM trusted_members;

            DROP TABLE trusted_members;

            ALTER TABLE trusted_members_new RENAME TO trusted_members;

            PRAGMA foreign_keys=ON;
        """)
        conn.commit()
        print("[DB] trusted_members rebuilt successfully.")
    except Exception as e:
        print(f"[DB] Migration (trusted_members FK fix): {e}")


def _trusted_members_needs_rebuild(conn) -> bool:
    """
    True only if trusted_members still carries the bad FK to users.user_id.

    Checked with PRAGMA foreign_key_list rather than assumed, so the expensive
    and slightly dangerous table rebuild happens once in the lifetime of a
    database instead of on every boot.
    """
    try:
        fks = conn.execute("PRAGMA foreign_key_list(trusted_members)").fetchall()
    except sqlite3.OperationalError:
        return False  # Table doesn't exist yet — create_schema builds it correctly.
    # Row layout: (id, seq, table, from, to, on_update, on_delete, match)
    return any(str(row[2]).lower() == "users" for row in fks)


# ---------------------------------------------------------------------------
# Users (2FA)
# ---------------------------------------------------------------------------

def insert_user(conn, info):
    """info: (user_id, secret, verified)"""
    _exec(conn, "INSERT INTO users(user_id, secret, verified) VALUES (?,?,?)", info)


def get_last_totp_step(conn, user_id: int):
    """
    Return the last TOTP time-step this user successfully consumed, or None.

    Tolerates the column being absent so a database that has not been migrated
    yet degrades to 'no replay protection' rather than breaking every command.
    """
    try:
        cur = conn.execute("SELECT last_totp_step FROM users WHERE user_id=?", (user_id,))
    except sqlite3.OperationalError:
        return None
    row = cur.fetchone()
    return row[0] if row else None


def set_last_totp_step(conn, user_id: int, step: int):
    """Record the TOTP time-step just consumed by a successful verification."""
    try:
        _exec(conn, "UPDATE users SET last_totp_step=? WHERE user_id=?", (step, user_id))
    except sqlite3.OperationalError:
        pass  # Column missing on an unmigrated DB — nothing to record.


def check_user(conn, user_id: int) -> bool:
    cur = conn.execute("SELECT EXISTS(SELECT 1 FROM users WHERE user_id=?)", (user_id,))
    return bool(cur.fetchone()[0])


def check_verified(conn, user_id: int) -> int:
    cur = conn.execute("SELECT verified FROM users WHERE user_id=?", (user_id,))
    row = cur.fetchone()
    return row[0] if row else 0


def get_secret(conn, user_id: int):
    cur = conn.execute("SELECT secret FROM users WHERE user_id=?", (user_id,))
    row = cur.fetchone()
    return row[0] if row else None


def verify(conn, user_id: int):
    _exec(conn, "UPDATE users SET verified=1 WHERE user_id=?", (user_id,))


def delete_user(conn, user_id: int):
    _exec(conn, "DELETE FROM users WHERE user_id=?", (user_id,))


# ---------------------------------------------------------------------------
# Guilds
# ---------------------------------------------------------------------------

def check_guild(conn, guild_id: int) -> bool:
    key = _ckey(conn, "check_guild", guild_id)
    cached = _cache_get(key)
    if cached is not _MISS:
        return cached
    cur = conn.execute("SELECT EXISTS(SELECT 1 FROM guilds WHERE guild_id=?)", (guild_id,))
    return _cache_put(key, bool(cur.fetchone()[0]))


def init_guild(conn, guild_id: int, log_channel: int, announcement_channel: int = None):
    """
    Initialize a guild with minimal required fields.

    Webhook protection ON by default. Name filter starts in 'flag' mode —
    matches are logged for a moderator to judge rather than acted on
    automatically, because a fresh server has untested patterns and an
    auto-ban on a false positive cannot be undone in bulk. Raise it with
    /name-filter set-action once the patterns are proven.
    """
    _exec(conn,
        """INSERT INTO guilds(guild_id, log_channel, announcement_channel,
                              webhook_protection, name_filter_action)
           VALUES (?,?,?,1,'flag')""",
        (guild_id, log_channel, announcement_channel))
    if announcement_channel:
        try:
            _exec(conn, "INSERT INTO channel_table(channel_id, guild_id) VALUES (?,?)",
                  (announcement_channel, guild_id))
        except sqlite3.IntegrityError:
            pass
    invalidate_guild(conn, guild_id)


def insert_guild(conn, info):
    """Legacy insert: info=(guild_id, event_channel, announcement_channel, log_channel)."""
    _exec(conn,
        "INSERT INTO guilds(guild_id, event_channel, announcement_channel, log_channel, webhook_protection) VALUES (?,?,?,?,1)",
        info)


def delete_guild(conn, guild_id: int):
    _exec(conn, "DELETE FROM trusted_members WHERE guild_id=?", (guild_id,))
    _exec(conn, "DELETE FROM channel_table WHERE guild_id=?", (guild_id,))
    _exec(conn, "DELETE FROM link_whitelist WHERE guild_id=?", (guild_id,))
    _exec(conn, "DELETE FROM link_managers WHERE guild_id=?", (guild_id,))
    _exec(conn, "DELETE FROM safe_roles WHERE guild_id=?", (guild_id,))
    _exec(conn, "DELETE FROM link_filter_whitelist WHERE guild_id=?", (guild_id,))
    _exec(conn, "DELETE FROM webhook_temp_disable WHERE guild_id=?", (guild_id,))
    _exec(conn, "DELETE FROM name_filters WHERE guild_id=?", (guild_id,))
    _exec(conn, "DELETE FROM verification_config WHERE guild_id=?", (guild_id,))
    _exec(conn, "DELETE FROM guild_branding WHERE guild_id=?", (guild_id,))
    _exec(conn, "DELETE FROM guilds WHERE guild_id=?", (guild_id,))
    invalidate_guild(conn, guild_id)


def get_log_channel(conn, guild_id: int):
    cur = conn.execute("SELECT log_channel FROM guilds WHERE guild_id=?", (guild_id,))
    row = cur.fetchone()
    return row[0] if row else None


def set_log_channel(conn, guild_id: int, channel_id: int):
    _exec(conn, "UPDATE guilds SET log_channel=? WHERE guild_id=?", (channel_id, guild_id))
    invalidate_guild(conn, guild_id)


def get_event_channel(conn, guild_id: int):
    cur = conn.execute("SELECT event_channel FROM guilds WHERE guild_id=?", (guild_id,))
    row = cur.fetchone()
    return row[0] if row else None


def get_link_filter_enabled(conn, guild_id: int) -> bool:
    key = _ckey(conn, "link_filter_enabled", guild_id)
    cached = _cache_get(key)
    if cached is not _MISS:
        return cached
    cur = conn.execute("SELECT link_filter_enabled FROM guilds WHERE guild_id=?", (guild_id,))
    row = cur.fetchone()
    return _cache_put(key, bool(row[0]) if row else False)


def set_link_filter_enabled(conn, guild_id: int, enabled: bool):
    _exec(conn, "UPDATE guilds SET link_filter_enabled=? WHERE guild_id=?", (int(enabled), guild_id))
    invalidate_guild(conn, guild_id)


def toggle_link_filter(conn, guild_id: int) -> bool:
    """Toggle and return the new state."""
    current = get_link_filter_enabled(conn, guild_id)
    new_state = not current
    set_link_filter_enabled(conn, guild_id, new_state)
    return new_state


def get_panic_active(conn, guild_id: int) -> bool:
    cur = conn.execute("SELECT panic_active FROM guilds WHERE guild_id=?", (guild_id,))
    row = cur.fetchone()
    return bool(row[0]) if row else False


def set_panic_active(conn, guild_id: int, active: bool):
    _exec(conn, "UPDATE guilds SET panic_active=? WHERE guild_id=?", (int(active), guild_id))


def get_announce_timeout(conn, guild_id: int) -> int:
    cur = conn.execute("SELECT announce_timeout FROM guilds WHERE guild_id=?", (guild_id,))
    row = cur.fetchone()
    return row[0] if row else 300


def set_announce_timeout(conn, guild_id: int, seconds: int):
    _exec(conn, "UPDATE guilds SET announce_timeout=? WHERE guild_id=?", (seconds, guild_id))
    invalidate_guild(conn, guild_id)


# ---------------------------------------------------------------------------
# Webhook settings
# ---------------------------------------------------------------------------

def check_webhook(conn, guild_id: int) -> bool:
    cur = conn.execute("SELECT webhook_protection FROM guilds WHERE guild_id=?", (guild_id,))
    row = cur.fetchone()
    return bool(row[0]) if row else False


def check_verified_bots(conn, guild_id: int) -> bool:
    cur = conn.execute("SELECT verified_bots FROM guilds WHERE guild_id=?", (guild_id,))
    row = cur.fetchone()
    return bool(row[0]) if row else False


def set_webhook_parameters(conn, info):
    """info: (webhook_protection, verified_bots, guild_id)"""
    _exec(conn,
        "UPDATE guilds SET webhook_protection=?, verified_bots=? WHERE guild_id=?",
        info)
    invalidate_guild(conn, info[2])


# ---------------------------------------------------------------------------
# Webhook temporary disable
# ---------------------------------------------------------------------------

def set_webhook_temp_disable(conn, guild_id: int, disabled_by: int, expires_iso: str):
    _exec(conn,
        """INSERT INTO webhook_temp_disable(guild_id, disabled_by, expires_at)
           VALUES (?,?,?)
           ON CONFLICT(guild_id) DO UPDATE SET disabled_by=excluded.disabled_by, expires_at=excluded.expires_at""",
        (guild_id, disabled_by, expires_iso))


def get_webhook_temp_disable(conn, guild_id: int):
    """Return the expires_at ISO string, or None if not temporarily disabled."""
    cur = conn.execute(
        "SELECT expires_at FROM webhook_temp_disable WHERE guild_id=?", (guild_id,))
    row = cur.fetchone()
    return row[0] if row else None


def clear_webhook_temp_disable(conn, guild_id: int):
    _exec(conn, "DELETE FROM webhook_temp_disable WHERE guild_id=?", (guild_id,))


# ---------------------------------------------------------------------------
# Trusted members (Announcers)
# ---------------------------------------------------------------------------

def authorise_member(conn, info):
    """info: (guild_id, member_id)"""
    _exec(conn, "INSERT INTO trusted_members(guild_id, member_id) VALUES (?,?)", info)


def deauthorise_member(conn, info):
    """info: (guild_id, member_id)"""
    _exec(conn, "DELETE FROM trusted_members WHERE guild_id=? AND member_id=?", info)


def check_authorised(conn, info) -> bool:
    """info: (guild_id, member_id)"""
    cur = conn.execute(
        "SELECT EXISTS(SELECT 1 FROM trusted_members WHERE guild_id=? AND member_id=?)",
        info)
    return bool(cur.fetchone()[0])


def get_trusted_members(conn, guild_id: int) -> list:
    cur = conn.execute("SELECT member_id FROM trusted_members WHERE guild_id=?", (guild_id,))
    return [row[0] for row in cur.fetchall()]


# ---------------------------------------------------------------------------
# Announcement channels
# ---------------------------------------------------------------------------

def insert_channel(conn, info):
    """info: (channel_id, guild_id)"""
    _exec(conn, "INSERT INTO channel_table(channel_id, guild_id) VALUES (?,?)", info)


def delete_channel(conn, channel_id: int):
    _exec(conn, "DELETE FROM channel_table WHERE channel_id=?", (channel_id,))


def get_channels(conn, guild_id: int) -> list:
    cur = conn.execute("SELECT channel_id FROM channel_table WHERE guild_id=?", (guild_id,))
    return [row[0] for row in cur.fetchall()]


def get_announcement_channel(conn, guild_id: int):
    cur = conn.execute("SELECT announcement_channel FROM guilds WHERE guild_id=?", (guild_id,))
    row = cur.fetchone()
    return row[0] if row else None


# ---------------------------------------------------------------------------
# Active announcements (permission grant tracking)
# ---------------------------------------------------------------------------

def insert_active_announcement(conn, info):
    """info: (channel_id, member_id) — inserts or refreshes the session timestamp."""
    _exec(conn, "INSERT OR REPLACE INTO active_announcements(channel_id, member_id) VALUES (?,?)", info)


def record_announcement_grant(conn, guild_id: int, channel_id: int, member_id: int, expires_at: int):
    """
    Persist a temporary announcement permission grant.

    The in-memory revocation task dies with the process, so without this a
    restart during an active window left the member holding send_messages and
    mention_everyone permanently. Reconciled on startup by
    get_pending_announcement_grants().
    """
    _exec(conn,
        """INSERT OR REPLACE INTO active_announcements(channel_id, member_id, guild_id, expires_at)
           VALUES (?,?,?,?)""",
        (channel_id, member_id, guild_id, expires_at))


def get_pending_announcement_grants(conn) -> list:
    """
    Return every persisted grant as (guild_id, channel_id, member_id, expires_at).

    Rows written before this column existed have expires_at NULL; they are
    returned with 0 so startup treats them as already expired and revokes them.
    """
    try:
        cur = conn.execute(
            """SELECT COALESCE(guild_id, 0), channel_id, member_id, COALESCE(expires_at, 0)
               FROM active_announcements""")
    except sqlite3.OperationalError:
        return []
    return cur.fetchall()


def delete_active_announcement(conn, info):
    """info: (channel_id, member_id)"""
    _exec(conn, "DELETE FROM active_announcements WHERE channel_id=? AND member_id=?", info)


def get_active_announcements_users(conn, channel_id: int) -> list:
    cur = conn.execute("SELECT member_id FROM active_announcements WHERE channel_id=?", (channel_id,))
    return [row[0] for row in cur.fetchall()]


def remove_inactive_announcements(conn):
    _exec(conn,
        "DELETE FROM active_announcements WHERE timestamp <= datetime('now', '-10 minutes')")


# ---------------------------------------------------------------------------
# Link whitelist
# ---------------------------------------------------------------------------

def add_link_whitelist(conn, guild_id: int, link_type: str, url: str, added_by: int) -> bool:
    try:
        _exec(conn,
            "INSERT INTO link_whitelist(guild_id, type, url, added_by) VALUES (?,?,?,?)",
            (guild_id, link_type, url, added_by))
        invalidate_guild(conn, guild_id)
        return True
    except sqlite3.IntegrityError:
        return False  # Already exists


def remove_link_whitelist(conn, guild_id: int, url: str) -> bool:
    cur = _exec(conn,
        "DELETE FROM link_whitelist WHERE guild_id=? AND url=?",
        (guild_id, url))
    invalidate_guild(conn, guild_id)
    return cur.rowcount > 0


def get_link_whitelist(conn, guild_id: int) -> list:
    key = _ckey(conn, "link_whitelist", guild_id)
    cached = _cache_get(key)
    if cached is not _MISS:
        return cached
    cur = conn.execute(
        "SELECT type, url FROM link_whitelist WHERE guild_id=? ORDER BY type, url",
        (guild_id,))
    return _cache_put(key, cur.fetchall())


# ---------------------------------------------------------------------------
# Link filter entity whitelist (channels, roles, users, categories)
# ---------------------------------------------------------------------------

def add_filter_exempt(conn, guild_id: int, entity_type: str, entity_id: int, added_by: int) -> bool:
    """Exempt a channel/role/user/category from the link filter."""
    try:
        _exec(conn,
            "INSERT INTO link_filter_whitelist(guild_id, entity_type, entity_id, added_by) VALUES (?,?,?,?)",
            (guild_id, entity_type, entity_id, added_by))
        invalidate_guild(conn, guild_id)
        return True
    except sqlite3.IntegrityError:
        return False


def remove_filter_exempt(conn, guild_id: int, entity_type: str, entity_id: int) -> bool:
    cur = _exec(conn,
        "DELETE FROM link_filter_whitelist WHERE guild_id=? AND entity_type=? AND entity_id=?",
        (guild_id, entity_type, entity_id))
    invalidate_guild(conn, guild_id)
    return cur.rowcount > 0


def get_filter_exemptions(conn, guild_id: int) -> list:
    """Returns list of (entity_type, entity_id) tuples."""
    key = _ckey(conn, "filter_exemptions", guild_id)
    cached = _cache_get(key)
    if cached is not _MISS:
        return cached
    cur = conn.execute(
        "SELECT entity_type, entity_id FROM link_filter_whitelist WHERE guild_id=? ORDER BY entity_type",
        (guild_id,))
    return _cache_put(key, cur.fetchall())


def is_filter_exempt(conn, guild_id: int, entity_type: str, entity_id: int) -> bool:
    """Resolved from the cached exemption list — no query on the hot path."""
    return (entity_type, entity_id) in get_filter_exemptions(conn, guild_id)


def is_filter_exempt_by_roles(conn, guild_id: int, role_ids: list) -> bool:
    """Check if ANY of the given role IDs are exempt."""
    if not role_ids:
        return False
    exempt_roles = {eid for etype, eid in get_filter_exemptions(conn, guild_id) if etype == 'role'}
    if not exempt_roles:
        return False
    return any(rid in exempt_roles for rid in role_ids)


# ---------------------------------------------------------------------------
# Safe roles
# ---------------------------------------------------------------------------

def add_safe_role(conn, guild_id: int, role_id: int) -> bool:
    try:
        _exec(conn, "INSERT INTO safe_roles(guild_id, role_id) VALUES (?,?)", (guild_id, role_id))
        return True
    except sqlite3.IntegrityError:
        return False


def remove_safe_role(conn, guild_id: int, role_id: int) -> bool:
    cur = _exec(conn, "DELETE FROM safe_roles WHERE guild_id=? AND role_id=?", (guild_id, role_id))
    return cur.rowcount > 0


def is_safe_role(conn, guild_id: int, role_id: int) -> bool:
    cur = conn.execute(
        "SELECT EXISTS(SELECT 1 FROM safe_roles WHERE guild_id=? AND role_id=?)",
        (guild_id, role_id))
    return bool(cur.fetchone()[0])


def get_safe_roles(conn, guild_id: int) -> list:
    cur = conn.execute("SELECT role_id FROM safe_roles WHERE guild_id=?", (guild_id,))
    return [row[0] for row in cur.fetchall()]


# ---------------------------------------------------------------------------
# Link managers
# ---------------------------------------------------------------------------

def add_link_manager(conn, guild_id: int, member_id: int) -> bool:
    try:
        _exec(conn,
            "INSERT INTO link_managers(guild_id, member_id) VALUES (?,?)",
            (guild_id, member_id))
        return True
    except sqlite3.IntegrityError:
        return False


def remove_link_manager(conn, guild_id: int, member_id: int) -> bool:
    cur = _exec(conn,
        "DELETE FROM link_managers WHERE guild_id=? AND member_id=?",
        (guild_id, member_id))
    return cur.rowcount > 0


def is_link_manager(conn, guild_id: int, member_id: int) -> bool:
    cur = conn.execute(
        "SELECT EXISTS(SELECT 1 FROM link_managers WHERE guild_id=? AND member_id=?)",
        (guild_id, member_id))
    return bool(cur.fetchone()[0])


def get_link_managers(conn, guild_id: int) -> list:
    cur = conn.execute("SELECT member_id FROM link_managers WHERE guild_id=?", (guild_id,))
    return [row[0] for row in cur.fetchall()]


# ---------------------------------------------------------------------------
# Panic backups
# ---------------------------------------------------------------------------

def save_panic_role_backup(conn, guild_id: int, role_id: int, perms_value: int):
    _exec(conn,
        "INSERT INTO panic_role_backup(guild_id, role_id, perms_value) VALUES (?,?,?)",
        (guild_id, role_id, perms_value))


def save_panic_channel_backup(conn, guild_id: int, channel_id: int, allow_value: int, deny_value: int):
    _exec(conn,
        "INSERT INTO panic_channel_backup(guild_id, channel_id, allow_value, deny_value) VALUES (?,?,?,?)",
        (guild_id, channel_id, allow_value, deny_value))


def get_panic_role_backups(conn, guild_id: int) -> list:
    cur = conn.execute(
        "SELECT role_id, perms_value FROM panic_role_backup WHERE guild_id=?", (guild_id,))
    return cur.fetchall()


def get_panic_channel_backups(conn, guild_id: int) -> list:
    cur = conn.execute(
        "SELECT channel_id, allow_value, deny_value FROM panic_channel_backup WHERE guild_id=?",
        (guild_id,))
    return cur.fetchall()


def clear_panic_backups(conn, guild_id: int):
    _exec(conn, "DELETE FROM panic_role_backup WHERE guild_id=?", (guild_id,))
    _exec(conn, "DELETE FROM panic_channel_backup WHERE guild_id=?", (guild_id,))


# ---------------------------------------------------------------------------
# Embeds
# ---------------------------------------------------------------------------

def insert_embed(conn, guild_id: int, channel_id: int, message_id: int, author_id: int,
                 title, description, color: int, footer, image_url):
    _exec(conn,
        """INSERT INTO embeds(guild_id, channel_id, message_id, author_id,
                              title, description, color, footer, image_url)
           VALUES (?,?,?,?,?,?,?,?,?)""",
        (guild_id, channel_id, message_id, author_id, title, description, color, footer, image_url))


def get_embed(conn, guild_id: int, message_id: int):
    """Return embed record as dict, or None if not found in this guild."""
    cur = conn.execute(
        """SELECT message_id, channel_id, author_id, title, description,
                  color, footer, image_url, created_at
           FROM embeds WHERE guild_id=? AND message_id=?""",
        (guild_id, message_id))
    row = cur.fetchone()
    if not row:
        return None
    keys = ('message_id', 'channel_id', 'author_id', 'title', 'description',
            'color', 'footer', 'image_url', 'created_at')
    return dict(zip(keys, row, strict=True))


def update_embed(conn, message_id: int, title, description, color: int, footer, image_url):
    _exec(conn,
        """UPDATE embeds SET title=?, description=?, color=?, footer=?, image_url=?
           WHERE message_id=?""",
        (title, description, color, footer, image_url, message_id))


def delete_embed(conn, message_id: int):
    _exec(conn, "DELETE FROM embeds WHERE message_id=?", (message_id,))


# ---------------------------------------------------------------------------
# Name filters
# ---------------------------------------------------------------------------

def insert_name_filter(conn, guild_id: int, filter_type: str, pattern: str, added_by: int) -> bool:
    """Insert a name filter. Returns False if it already exists."""
    try:
        _exec(conn,
            "INSERT INTO name_filters(guild_id, type, pattern, added_by) VALUES (?,?,?,?)",
            (guild_id, filter_type, pattern, added_by))
        invalidate_guild(conn, guild_id)
        return True
    except sqlite3.IntegrityError:
        return False


def get_name_filters(conn, guild_id: int) -> list:
    """Return all name filters for a guild as a list of dicts."""
    key = _ckey(conn, "name_filters", guild_id)
    cached = _cache_get(key)
    if cached is not _MISS:
        return cached
    cur = conn.execute(
        "SELECT id, type, pattern FROM name_filters WHERE guild_id=? ORDER BY type, id",
        (guild_id,))
    return _cache_put(key, [{'id': r[0], 'type': r[1], 'pattern': r[2]} for r in cur.fetchall()])


def delete_name_filter(conn, guild_id: int, filter_id: int) -> bool:
    """Delete a filter by ID within the guild. Returns False if not found."""
    cur = _exec(conn,
        "DELETE FROM name_filters WHERE id=? AND guild_id=?",
        (filter_id, guild_id))
    invalidate_guild(conn, guild_id)
    return cur.rowcount > 0


def get_name_filter_action(conn, guild_id: int) -> str:
    """Return the configured action for name filter matches (default: 'ban')."""
    key = _ckey(conn, "name_filter_action", guild_id)
    cached = _cache_get(key)
    if cached is not _MISS:
        return cached
    cur = conn.execute(
        "SELECT name_filter_action FROM guilds WHERE guild_id=?", (guild_id,))
    row = cur.fetchone()
    return _cache_put(key, (row[0] or 'ban') if row else 'ban')


def set_name_filter_action(conn, guild_id: int, action: str):
    _exec(conn,
        "UPDATE guilds SET name_filter_action=? WHERE guild_id=?",
        (action, guild_id))
    invalidate_guild(conn, guild_id)


# ---------------------------------------------------------------------------
# Member verification
# ---------------------------------------------------------------------------

def set_verification_config(conn, guild_id: int, channel_id: int, role_id: int,
                            min_account_age: int = 0, log_channel_id: int = None):
    """
    Create or update a guild's verification setup.

    Upsert rather than insert so re-running /verify-setup reconfigures instead
    of failing on the primary key. log_channel_id of None keeps whatever was
    already configured, so re-running setup without naming a join channel does
    not silently reset it.
    """
    _exec(conn,
        """INSERT INTO verification_config(guild_id, channel_id, role_id,
                                           min_account_age, log_channel_id, enabled)
           VALUES (?,?,?,?,?,1)
           ON CONFLICT(guild_id) DO UPDATE SET
               channel_id      = excluded.channel_id,
               role_id         = excluded.role_id,
               min_account_age = excluded.min_account_age,
               log_channel_id  = COALESCE(excluded.log_channel_id,
                                          verification_config.log_channel_id),
               enabled         = 1""",
        (guild_id, channel_id, role_id, min_account_age, log_channel_id))
    invalidate_guild(conn, guild_id)


def set_verification_log_channel(conn, guild_id: int, channel_id):
    """Set (or clear, with None) the dedicated join-log channel."""
    _exec(conn, "UPDATE verification_config SET log_channel_id=? WHERE guild_id=?",
          (channel_id, guild_id))
    invalidate_guild(conn, guild_id)


def get_verification_config(conn, guild_id: int):
    """Return the guild's verification config as a dict, or None if unset."""
    key = _ckey(conn, "verification_config", guild_id)
    cached = _cache_get(key)
    if cached is not _MISS:
        return cached
    try:
        cur = conn.execute(
            """SELECT guild_id, channel_id, role_id, panel_message_id, enabled,
                      min_account_age, log_channel_id
               FROM verification_config WHERE guild_id=?""",
            (guild_id,))
    except sqlite3.OperationalError:
        return None
    row = cur.fetchone()
    if not row:
        return _cache_put(key, None)
    keys = ('guild_id', 'channel_id', 'role_id', 'panel_message_id', 'enabled',
            'min_account_age', 'log_channel_id')
    return _cache_put(key, dict(zip(keys, row, strict=True)))


def set_verification_panel(conn, guild_id: int, message_id: int):
    """Remember which message holds the Verify button, so it can be replaced."""
    _exec(conn, "UPDATE verification_config SET panel_message_id=? WHERE guild_id=?",
          (message_id, guild_id))
    invalidate_guild(conn, guild_id)


def set_verification_enabled(conn, guild_id: int, enabled: bool):
    _exec(conn, "UPDATE verification_config SET enabled=? WHERE guild_id=?",
          (int(enabled), guild_id))
    invalidate_guild(conn, guild_id)


def delete_verification_config(conn, guild_id: int) -> bool:
    cur = _exec(conn, "DELETE FROM verification_config WHERE guild_id=?", (guild_id,))
    invalidate_guild(conn, guild_id)
    return cur.rowcount > 0


def get_all_verification_configs(conn) -> list:
    """Every configured guild — used to re-register persistent views on startup."""
    try:
        cur = conn.execute(
            "SELECT guild_id, channel_id, role_id FROM verification_config WHERE enabled=1")
    except sqlite3.OperationalError:
        return []
    return cur.fetchall()


# ---------------------------------------------------------------------------
# Guild branding
# ---------------------------------------------------------------------------

DEFAULT_BRAND_COLOR = 0x5865F2  # Discord blurple


def set_guild_branding(conn, guild_id: int, color=None, footer=None, icon_url=None):
    _exec(conn,
        """INSERT INTO guild_branding(guild_id, color, footer, icon_url)
           VALUES (?,?,?,?)
           ON CONFLICT(guild_id) DO UPDATE SET
               color    = COALESCE(excluded.color,    guild_branding.color),
               footer   = COALESCE(excluded.footer,   guild_branding.footer),
               icon_url = COALESCE(excluded.icon_url, guild_branding.icon_url)""",
        (guild_id, color, footer, icon_url))
    invalidate_guild(conn, guild_id)


def get_guild_branding(conn, guild_id: int) -> dict:
    """Branding for a guild, falling back to defaults."""
    key = _ckey(conn, "guild_branding", guild_id)
    cached = _cache_get(key)
    if cached is not _MISS:
        return cached
    try:
        cur = conn.execute(
            "SELECT color, footer, icon_url FROM guild_branding WHERE guild_id=?", (guild_id,))
        row = cur.fetchone()
    except sqlite3.OperationalError:
        row = None
    return _cache_put(key, {
        'color':    (row[0] if row and row[0] is not None else DEFAULT_BRAND_COLOR),
        'footer':   (row[1] if row else None),
        'icon_url': (row[2] if row else None),
    })


def get_recent_embeds(conn, guild_id: int, channel_id: int = None, limit: int = 10) -> list:
    """Return up to `limit` most recent embeds as a list of dicts."""
    if channel_id:
        cur = conn.execute(
            """SELECT message_id, channel_id, author_id, title,
                      CAST(strftime('%s', created_at) AS INTEGER) as created_ts
               FROM embeds WHERE guild_id=? AND channel_id=?
               ORDER BY created_at DESC LIMIT ?""",
            (guild_id, channel_id, limit))
    else:
        cur = conn.execute(
            """SELECT message_id, channel_id, author_id, title,
                      CAST(strftime('%s', created_at) AS INTEGER) as created_ts
               FROM embeds WHERE guild_id=?
               ORDER BY created_at DESC LIMIT ?""",
            (guild_id, limit))
    keys = ('message_id', 'channel_id', 'author_id', 'title', 'created_ts')
    return [dict(zip(keys, row, strict=True)) for row in cur.fetchall()]
