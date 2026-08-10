# SecurityBot — Discord Server Security Bot

A production-grade Discord security bot for communities that take their server's safety seriously. SecurityBot combines multi-factor authentication, advanced link scanning, automated name filtering, webhook protection, and full-server panic lockdown — all controlled through a strict 2FA-gated permission hierarchy.

Designed for one server per instance. Easy to self-host. Built with Python + py-cord.

---

## Why SecurityBot?

Most Discord bots treat security as an afterthought. SecurityBot was built security-first:

- **Every sensitive action requires a live 2FA code** — no exceptions.
- **Five-pass link scanner** that catches obfuscated, percent-encoded, markdown-split, and Unicode-spoofed URLs that other bots miss entirely.
- **Name filter** with regex and phrase matching — flags impersonators and fake support accounts on join for a moderator to judge, or acts automatically once your patterns are proven.
- **Webhook protection** deletes unauthorized webhooks the moment they appear.
- **Panic mode** backs up your entire server's permissions, locks everything down in seconds, and restores from backup on command.
- **Full audit trail** — every state-changing action produces a structured log embed in your designated channel.

---

## Feature Overview

### 2FA Authentication System

- TOTP-based 2FA (compatible with Authy, Google Authenticator, any TOTP app)
- QR code rendered in memory — the secret never touches disk
- Secrets encrypted at rest (Fernet) when `ENCRYPTION_KEY` is set
- Each code is single-use: a code already accepted is refused for the rest of its window
- No self-service recovery: a lost authenticator is re-issued by an owner via `/reset-user`, and logged

### Member Verification (Captcha)

A `Verify` button posts to a channel of your choice. Members click it, solve a short maths captcha, and receive a role.

- **The challenge exists only inside the image** — the message never contains the problems as text, so a script cannot read and solve them
- Ephemeral: only the member sees their own captcha
- Numeric keypad with a live progress counter
- **Layered checks:** minimum account age, response timing, per-user attempt limits, and short session expiry
- The panel button survives restarts (persistent view)
- Refuses to configure a role carrying Administrator or Manage Server

### Permission Hierarchy — "locksmith, not landlord"

Authority is split by **scope**, so the bot can run in servers its operator does not own.

```
GLOBAL OPERATOR (MASTER_USER_ID in .env)
  └── The person hosting the bot. Holds the emergency DM hatch only:
      panic / recover-panic. Deliberately NOT the day-to-day authority —
      a server must never wait on the operator to run itself.

SERVER OWNER (Discord guild.owner_id)
  └── Full authority over their own server: setup, config, granting
      keycards, name-filter actions, panic, recover.

LINK MANAGER (added via /add-linkmanager)
  └── Manage the URL whitelist — requires 2FA verified

ANNOUNCER (added via /add-announcer)
  └── Announcements, embeds, and name-filter patterns — requires 2FA verified

UNREGISTERED USER
  └── Cannot use any command
```

The global operator still passes every server-owner check, so it can support a server hands-on when asked. The difference is that the server owner is never _blocked_ waiting for it.

### Link Scanner — 5-Pass Detection Engine

Runs on every message and every edit. Handles the following evasion techniques:

| Technique                    | Example                                                   |
| ---------------------------- | --------------------------------------------------------- |
| Split URL across newlines    | `ht\ntp://evil.com`                                       |
| Blockquote-split URL         | `> ht\n> tp\n> ://evil.com`                               |
| Markdown formatting in URL   | `https*://*evil.com`                                      |
| Extra/mixed slashes          | `https:////\\\\evil.com`                                  |
| Percent-encoded domain       | `%68%74%74%70%73://evil.com`                              |
| Double-encoded domain        | `%2568%2574...`                                           |
| Unicode lookalike dots       | `evil。com` → `evil.com`                                  |
| Unicode lookalike slashes    | `https:⁄⁄evil.com`                                        |
| Unicode lookalike colons     | `https：//evil.com`                                       |
| Zero-width / invisible chars | `ev​il.com`                                               |
| Angle bracket wrapping       | `<https://evil.com>`                                      |
| Markdown hyperlinks          | `[click me](https://evil.com)`                            |
| Alternative protocols        | `ftp://`, `discord://`, `javascript:`, `mailto:`, `tg://` |
| Mixed-case protocols         | `dIsCoRd://`, `mAiLtO:`                                   |
| Bare shortener domains       | `discord.gg/xxx`, `t.me/xxx`, `bit.ly/xxx`                |

Whitelist supports **domain-level** (allows all subdomains) and **exact URL** matching. Channels, categories, roles, and individual users can be fully exempted.

### Name Filter

Automatically acts on members whose username or nickname matches a configured pattern. Fires on join, nickname changes, and global username changes.

- **Phrase filters** — case-insensitive substring match (`support`, `admin`, `metamask`)
- **Regex filters** — full Python regex (`(?i)^mod`, `(?i) support$`)
- **Bulk import** — paste 50+ filters at once via Discord modal
- **Configurable action** — `flag` (default), `ban`, `kick`, or `timeout` with custom hours

**`flag` mode is the default and the recommended setting.** A match is _evidence_, not proof — so the bot writes a detailed log entry naming the member, the pattern that matched, and their account age, then leaves the decision to a moderator. This mirrors how the link filter works: the bot removes the content, a human judges the person.

Raise it to `ban`/`kick`/`timeout` only once your patterns are proven with `/name-filter test`. Automatic bans are fast but cannot be undone in bulk, and a single loose pattern will take out real members before anyone notices.

Existing servers keep whatever action they already had — upgrading does not silently change it.

- **Retroactive cleanse** — scan all current members against active filters in one command (owner-only, aborts if it would hit >25% of the server)
- Exempt: bot owner, server owner, server staff (Administrator / Ban / Kick / Manage Server / Timeout), announcers, link managers

### Webhook Protection

- Deletes any webhook created without going through the `/allow-webhook` command
- 30-minute temporary allow window when you need to add a legitimate webhook (CI/CD, etc.)
- Always-on by default when the server is set up
- Channel follower webhooks (Discord-native) are never deleted

### Panic Mode

Full server lockdown, available to the server owner or the global operator.

**What it does:**

1. Backs up all role permissions and channel overwrites to database
2. Strips dangerous permissions (admin, manage roles, ban, kick, etc.) from all roles
3. Deletes all server webhooks
4. Cancels all scheduled events
5. Locks all channels (denies view + send to @everyone)
6. DMs the server owner
7. Full restore available via `/recover`

Lockdown Requires: 2FA code + typing `CONFIRM LOCKDOWN` in a modal. No accidental triggers.

### Embed Builder

Send, edit, and delete rich embeds as the bot from within Discord — no dashboard needed.

- Modal-based builder with live preview before posting
- Forum channel support (creates a new thread)
- All embeds tracked in database for future edit/delete
- Supports title, description, custom color, footer, image URL
- 2FA required for all write operations

### Moderation Toolkit

- Role management — toggle, bulk apply, create
- Channel permission management — toggle access, sync category, restrict to single channel
- Thread locking — lock all threads in a channel or server-wide
- Member and role CSV export
- **Permission export** — full colour-coded Excel snapshot of every role's permissions at server level, per category, and per channel
- Channel permission override audit

### Audit Logging

Structured embed logs posted to your configured log channel for every security event:

- Message deletions by link filter (with full message content)
- Link whitelist changes
- Webhook activity
- 2FA events (setup, verify, reset)
- Name filter triggers (includes matched name, pattern, account age, action taken)
- Panic and recover events
- All admin changes (announcers, link managers, channels, timeouts)

---

## Setup

**Requirements:** Python 3.10+ · A Discord bot application with Message Content intent enabled

```bash
# 1. Clone / download the repo
git clone https://github.com/Nuelverse/Discord-Shield-Security-Bot
cd Discord-Shield-Security-Bot

# 2. Create virtual environment
python -m venv .venv
source .venv/bin/activate      # Linux/macOS
.venv\Scripts\activate         # Windows

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure environment
cp .env.example .env
# Edit .env with your values (see below)

# 5. Run
python bot.py
```

---

## Environment Variables

```env
BOT_TOKEN=your_discord_bot_token_here
MASTER_USER_ID=your_discord_user_id_here
ENCRYPTION_KEY=                    # Strongly recommended: encrypts 2FA secrets at rest
DEBUG_GUILD_ID=                    # Set to a guild ID for one-instance-per-server
DATABASE_PATH=database.db          # Optional: override the database file path
```

| Variable         | Required    | Description                                                                                                                                                                                                             |
| ---------------- | ----------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `BOT_TOKEN`      | Yes         | Discord Developer Portal → Your App → Bot → Token                                                                                                                                                                       |
| `MASTER_USER_ID` | Yes         | Your Discord user ID — this account has full bot control                                                                                                                                                                |
| `ENCRYPTION_KEY` | Recommended | Encrypts TOTP secrets at rest                                                                                                                                                                                           |
| `DEBUG_GUILD_ID` | No          | Pins slash commands to one guild. **Set it** when running one instance per server. **Leave empty** when one instance serves several servers. See "Two deployment models" below. |
| `DATABASE_PATH`  | No          | Path to the SQLite database file. Defaults to `database.db`                                                                                                                                                             |

> **Changing ownership:** `MASTER_USER_ID` is read from `.env` at startup. Transfer bot control to any Discord user by changing this value — no Discord application ownership transfer needed.

### Two deployment models

**One instance per server** — the intended model. Each client gets their own deployment, their own bot application and token, and their own database. Set `DEBUG_GUILD_ID` to that server's ID.

- Slash commands register **instantly** instead of taking up to an hour
- Complete isolation: a compromised token, a corrupted database, or a bad deploy affects exactly one client
- Cost: you maintain N deployments and roll updates out N times

**One instance, many servers** — leave `DEBUG_GUILD_ID` empty so commands register globally.

- One deployment to update
- Commands take up to an hour to appear after a change
- One database and one token shared across every server

> **Failure mode to know:** if `DEBUG_GUILD_ID` is set and you add that same bot to a *second* server, its slash commands will not appear there. The passive protections — link filter, name filter, webhook protection — still run, so the bot looks half-working rather than dead. Either clear the variable or give the new server its own instance.

### Encryption key

Without `ENCRYPTION_KEY`, TOTP secrets sit in `database.db` in plaintext — anyone who can read that file can generate valid 2FA codes for every privileged user. Generate a key with:

```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Any existing plaintext secrets are encrypted automatically on the next startup, and the bot logs how many it upgraded. **Back up `database.db` before setting the key**, and never lose or change it afterwards — rotating it makes every stored secret unreadable and forces all users to re-run `/create-2fa`.

### Discord Developer Portal Setup

1. Go to [discord.com/developers/applications](https://discord.com/developers/applications)
2. Create a new application, navigate to **Bot**
3. Enable **Message Content Intent**, **Server Members Intent**, **Presence Intent**
4. Copy the bot token → paste into `.env` as `BOT_TOKEN`
5. Under **OAuth2 → URL Generator**, select scopes: `bot`, `applications.commands`
6. Required bot permissions: `Administrator` (or at minimum: Manage Roles, Manage Channels, Ban Members, Kick Members, Manage Webhooks, Manage Threads, View Audit Log, Read/Send Messages, Embed Links, Attach Files, Manage Messages)

---

## First-Time Server Setup

1. Invite the bot to your server using the OAuth2 URL from the Developer Portal.
2. The **bot owner** (your `MASTER_USER_ID` account) runs `/create-2fa` → scans the QR code → runs `/verify`.
3. Bot owner runs `/setup-guild log_channel:<#channel> announcement_channel:<#channel> code:<2fa>`.
4. Add team members:
   - `/add-linkmanager member:<@user> code:<2fa>` — for link whitelist managers
   - `/add-announcer member:<@user> code:<2fa>` — for announcement posters
5. Each new team member runs `/create-2fa` → scans QR → runs `/verify`.
6. Enable the link filter: `/toggle-linkfilter code:<2fa>`
7. Whitelist any domains your server legitimately uses: `/allow-link type:domain`

---

## 2FA Onboarding Flow

```
Admin runs /add-linkmanager or /add-announcer
  → New member is DM'd with instructions
  → Member runs /create-2fa in the server
      → Bot responds ephemerally with a QR code (shown once)
      → Member scans QR in Authy / Google Authenticator
  → Member runs /verify code:<6-digit-totp>
      → 2FA confirmed — member can now use their assigned commands
```

> Scan QR codes with an authenticator app — **never** with Discord mobile's built-in camera (it opens links instead of reading TOTP).

---

## Command Reference

### 2FA & Account

| Command                   | Access                    | 2FA | Description                                                     |
| ------------------------- | ------------------------- | --- | --------------------------------------------------------------- |
| `/create-2fa`             | Registered users, owners  | No  | Generate a TOTP QR code. Shows the secret key for manual entry. |
| `/verify code`            | Anyone with pending setup | N/A | Confirm TOTP pairing with a 6-digit code.                       |
| `/reset-user member code` | Server owner, bot owner   | Yes | Wipe a user's 2FA for re-registration. DMs the reset user.      |

### Admin

| Command                                              | Access                  | 2FA | Description                                                                            |
| ---------------------------------------------------- | ----------------------- | --- | -------------------------------------------------------------------------------------- |
| `/setup-guild log_channel announcement_channel code` | Bot owner               | Yes | One-time server initialization.                                                        |
| `/add-announcer member code`                         | Server owner, bot owner | Yes | Add a user to announcers. DMs them setup instructions.                                 |
| `/remove-announcer member code`                      | Server owner, bot owner | Yes | Remove announce permissions.                                                           |
| `/add-linkmanager member code`                       | Server owner, bot owner | Yes | Add a user to link managers. DMs them setup instructions.                              |
| `/remove-linkmanager member code`                    | Server owner, bot owner | Yes | Remove link manager permissions.                                                       |
| `/add-channel channel code`                          | Server owner, bot owner | Yes | Add a channel to the announcement channels list.                                       |
| `/remove-channel channel code`                       | Server owner, bot owner | Yes | Remove a channel from the announcement channels list.                                  |
| `/set-logs channel code`                             | Server owner, bot owner | Yes | Change the log channel.                                                                |
| `/change-timeout seconds code`                       | Bot owner               | Yes | Set announcement permission window duration (30–3600s, default 300).                   |
| `/list option`                                       | Any registered user     | No  | List a config group: `announcers`, `link-managers`, `whitelist`, `channels`, `exempt`. |
| `/list-all`                                          | Server owner, bot owner | No  | Full server config overview in one embed.                                              |

### Link Filter

| Command                                                | Access                  | 2FA            | Description                                                                 |
| ------------------------------------------------------ | ----------------------- | -------------- | --------------------------------------------------------------------------- |
| `/allow-link type`                                     | Link managers, owners   | Yes (in modal) | Whitelist up to 10 domains or URLs at once. `domain` covers all subdomains. |
| `/remove-link url code`                                | Link managers, owners   | Yes            | Remove a URL from the whitelist.                                            |
| `/toggle-linkfilter code`                              | Bot owner               | Yes            | Enable or disable link scanning for this server.                            |
| `/add-whitelist-linkfilter entity_type target code`    | Server owner, bot owner | Yes            | Exempt a channel, category, role, or user from link scanning.               |
| `/remove-whitelist-linkfilter entity_type target code` | Server owner, bot owner | Yes            | Remove a link filter exemption.                                             |

### Webhooks

| Command               | Access    | 2FA | Description                                                                                |
| --------------------- | --------- | --- | ------------------------------------------------------------------------------------------ |
| `/allow-webhook code` | Bot owner | Yes | Open a 30-minute window for adding a legitimate webhook. Protection auto-re-enables after. |

### Announcements

| Command                  | Access             | 2FA | Description                                                                                               |
| ------------------------ | ------------------ | --- | --------------------------------------------------------------------------------------------------------- |
| `/announce channel code` | Announcers, owners | Yes | Grant temporary channel access (send, embed, attach, mention @everyone). Auto-revoked when timer expires. |

### Embeds

| Command                                 | Access              | 2FA | Description                                                          |
| --------------------------------------- | ------------------- | --- | -------------------------------------------------------------------- |
| `/embed send channel code`              | Announcers, owners  | Yes | Build and post an embed via modal with live preview.                 |
| `/embed edit message_id channel code`   | Announcers, owners  | Yes | Edit a previously sent embed. Pre-filled modal with current content. |
| `/embed delete message_id channel code` | Announcers, owners  | Yes | Delete a bot embed and remove its database record.                   |
| `/embed list [channel]`                 | Any registered user | No  | List 10 most recent bot embeds (optionally filtered by channel).     |

### Name Filter

| Command                                               | Access             | 2FA | Description                                                                              |
| ----------------------------------------------------- | ------------------ | --- | ---------------------------------------------------------------------------------------- |
| `/name-filter add phrase pattern code`                | Announcers, owners | Yes | Add a single case-insensitive phrase filter.                                             |
| `/name-filter add regex pattern code`                 | Announcers, owners | Yes | Add a regex filter. Validates syntax before saving.                                      |
| `/name-filter import phrase code`                     | Announcers, owners | Yes | Paste 50+ phrase filters at once via modal.                                              |
| `/name-filter import regex code`                      | Announcers, owners | Yes | Paste 50+ regex filters at once. Invalid patterns reported and skipped.                  |
| `/name-filter remove filter_id code`                  | Announcers, owners | Yes | Remove a filter by its ID.                                                               |
| `/name-filter list`                                   | Announcers, owners | No  | Post all active filters to the log channel (regex first, then phrase).                   |
| `/name-filter test name`                              | Announcers, owners | No  | Check if a name would be caught and which filter would match it.                         |
| `/name-filter set-action action code [timeout_hours]` | **Owners only**    | Yes | Set match action: `flag` (log only, default), `ban`, `kick`, or `timeout` (1–672 hours). |
| `/name-filter cleanse code`                           | **Owners only**    | Yes | Retroactively scan all current members. 5-minute guild cooldown.                         |

**Regex safety:** patterns are rejected if they exceed 200 characters or contain a nested quantifier such as `(a+)+` or `(x*)*`. Those can trigger catastrophic backtracking, and since filters run on every join and nickname change, one bad pattern would freeze the whole bot.

**Cleanse safety:** `cleanse` aborts without touching anyone if a run would action more than 25% of eligible members (and more than 10 people). A filter matching most of the server is almost always an over-broad pattern rather than a real attack, and bans cannot be undone in bulk. Narrow the filter with `/name-filter test` and run it again.

**Exemptions:** the bot owner, server owner, announcers, link managers, and anyone with Administrator / Ban / Kick / Manage Server / Timeout permissions are skipped — so a bad pattern can't remove the staff who need to fix it.

### Moderation

| Command                                   | Access                  | 2FA | Description                                                                                                                                                                           |
| ----------------------------------------- | ----------------------- | --- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `/role member role`                       | Server owner, bot owner | No  | Toggle a role on/off for a member.                                                                                                                                                    |
| `/bulk-role`                              | Server owner, bot owner | No  | Apply a role to multiple users at once (paste user IDs in modal).                                                                                                                     |
| `/new-role name [color]`                  | Server owner, bot owner | No  | Create a new role. `color` is an optional hex value.                                                                                                                                  |
| `/rename-channel channel new_name`        | Server owner, bot owner | No  | Rename a channel. Protects log and announcement channels.                                                                                                                             |
| `/toggle-channel channel role`            | Server owner, bot owner | No  | Toggle a role's access to a channel on/off.                                                                                                                                           |
| `/sync-channels category`                 | Server owner, bot owner | No  | Sync all channels in a category to category permissions.                                                                                                                              |
| `/restrict-channel member action channel` | Server owner, bot owner | No  | Restrict a member to one channel. `action`: `add` or `remove`.                                                                                                                        |
| `/lock-threads [channel]`                 | Server owner, bot owner | No  | Lock all active and archived threads in a channel or server-wide.                                                                                                                     |
| `/export`                                 | Server owner, bot owner | Yes | Export all server members and their roles as a CSV file.                                                                                                                              |
| `/export-category category`               | Server owner, bot owner | Yes | Export message history from all text channels in a category as a ZIP of CSVs.                                                                                                         |
| `/export-permissions`                     | Server owner, bot owner | Yes | Export every role's permissions to a colour-coded `.xlsx` file — server level on Sheet 1, category overrides on Sheet 2, channel overrides on Sheet 3. Green = allowed, red = denied. |
| `/list-overrides`                         | Server owner, bot owner | Yes | List all channels with user-specific permission overrides.                                                                                                                            |

### Verification

| Command                                             | Access      | 2FA | Description                                                                       |
| --------------------------------------------------- | ----------- | --- | --------------------------------------------------------------------------------- |
| `/verify-setup channel role code [min_account_age]` | Owners      | Yes | Configure verification and post the panel. Optional minimum account age in hours. |
| `/verify-panel code`                                | Owners      | Yes | Re-post the panel using saved settings (e.g. if the message was deleted).         |
| `/verify-toggle code`                               | Owners      | Yes | Enable/disable verification without losing the configuration.                     |
| `/verify-status`                                    | Any keycard | No  | View current channel, role, account-age rule, and challenges in flight.           |

Before configuring, make sure the bot's role sits **above** the verified role, or it cannot grant it. `/verify-setup` checks this and tells you if it's wrong.

### Panic

| Command         | Access | 2FA         | Description                                                                                       |
| --------------- | ------ | ----------- | ------------------------------------------------------------------------------------------------- |
| `/panic`        | Owners | Yes (modal) | Open confirmation modal. Requires typing `CONFIRM LOCKDOWN` + 2FA code. Locks down entire server. |
| `/recover code` | Owners | Yes         | Restore all role permissions and channel overwrites from panic backup.                            |

**DM triggers:** If you can't access the server (e.g. you were kicked), DM the bot:

```
panic <guild_id> <2fa_code> CONFIRM LOCKDOWN
recover-panic <guild_id> <2fa_code>
```

---

## Account Recovery

**There is no self-service recovery.** This is deliberate.

Single-use backup codes were removed. They looked like a safety net but worked as a second, weaker credential: shown once in a Discord message, they were routinely screenshotted into saved messages or a notes app.
At which point they could wipe the victim's 2FA over DM, pair their own authenticator, and inherit that person's bot access with no human ever noticing.

Losing an authenticator is now handled the way losing a building pass is: someone with authority re-issues it.

**If you lose access to your authenticator app:**

1. Ask a **server owner** to run `/reset-user @you code:<their 2FA>`
2. The bot clears your 2FA and DMs you — the reset is written to the audit log
3. Run `/create-2fa` in the server to pair a new authenticator

**Back up your authenticator, not your codes.** Use an app with its own encrypted backup (Authy, 1Password, Bitwarden), or add the TOTP key to a second device when you set it up. That protects you without creating a credential an attacker can steal.

### Operator lockout

The global operator (`MASTER_USER_ID`) is the one account nobody can reset in band — `/reset-user` needs a working 2FA code from whoever runs it.

That recovery is deliberately **out of band**, through infrastructure the operator already controls:

```sql
-- On the host, against your database:
DELETE FROM users WHERE user_id = <your_discord_user_id>;
```

Then run `/create-2fa` again. Anyone able to do this already holds your bot token and database, so it grants an attacker nothing new — but it means hosting access, rather than a screenshot in someone's notes app, is the last resort.

If a **server owner** is locked out, you as operator can reset them with `/reset-user`, since you pass every owner-level check.

---

## Customization

### Brand Color

The default embed color is Discord blurple (`#5865F2`). To change it:

Edit [cogs/embeds.py](cogs/embeds.py) line 32:

```python
BRAND_COLOR = 0x5865F2  # Change to your hex color, e.g. 0xFF5733
```

### 2FA App Name

The name shown in authenticator apps is set in [two_factor_helper.py](two_factor_helper.py):

```python
uri = pyotp.totp.TOTP(secret).provisioning_uri(
    name="Security Bot",       # Shown as the account label
    issuer_name="SecurityBot"  # Shown as the issuer
)
```

### Dangerous Permissions (Panic Mode)

Configure which permissions are stripped during panic in [config.json](config.json) under `"panic" → "dangerous_permissions"`.

---

## Running Tests

```bash
pip install -r requirements-dev.txt
pytest
```

---

## Tech Stack

- **Runtime:** Python 3.10+
- **Discord library:** [py-cord](https://github.com/Pycord-Development/pycord) (slash commands, modals, views)
- **Database:** SQLite with WAL mode + parameterized queries throughout (no SQL injection)
- **2FA:** [pyotp](https://github.com/pyauth/pyotp) (TOTP, RFC 6238 compliant)
- **QR codes:** [pyqrcode](https://github.com/mnooner256/pyqrcode) + pypng
- **Config:** python-dotenv
- **Encryption:** [cryptography](https://cryptography.io/) (Fernet, for secrets at rest)
- **Captcha rendering:** [Pillow](https://pillow.readthedocs.io/) (image-only verification challenges)
- **Excel export:** [openpyxl](https://openpyxl.readthedocs.io/) (permission audit workbooks)

---

## Security Notes

- All sensitive commands require a valid TOTP code verified at execution time — no session-based auth.
- **Each TOTP code is single-use.** A code that has already been accepted is refused for the rest of its 30-second window, so an observed code cannot be replayed against another command. Running two commands back to back means waiting for a fresh code.
- **TOTP secrets are encrypted at rest** with Fernet when `ENCRYPTION_KEY` is set, and existing plaintext secrets are migrated automatically on startup.
- There are no backup codes. Self-service recovery was removed because it let a phished Discord account be escalated into full bot access with no human in the loop; an owner must re-issue via `/reset-user`, which is logged.
- QR codes are rendered in memory and never written to disk, so the secret has no on-disk exposure window.
- User-supplied name-filter regexes are validated against catastrophic backtracking before being stored, since they execute on every join and nickname change.
- Verification captcha challenges are rendered image-only and use `secrets` for anything answer-determining, so answers cannot be read from message text or predicted from a seedable PRNG.
- `/name-filter cleanse` refuses to run when it would action more than 25% of eligible members.
- The SQLite database uses foreign key constraints, WAL mode, and parameterized queries throughout.
- Guild config reads are cached for 10 seconds and invalidated on write, so the message hot path does not block the event loop on SQLite.
- The link scanner runs 5 detection passes. Within the deep-scan pass, percent-decoding is applied iteratively (up to 3 decode iterations) to catch double-encoded URLs.
- Cogs load independently: a failure in one (e.g. a missing optional dependency) no longer prevents the bot from starting with the rest.

### Auditing

The project is checked with [bandit](https://bandit.readthedocs.io/) (SAST), [ruff](https://docs.astral.sh/ruff/) (including the `S`/`B`/`ASYNC` rule sets), and [pip-audit](https://pypi.org/project/pip-audit/) (dependency CVEs):

```bash
pip install bandit ruff pip-audit
bandit -r . -x ./.venv,./tests
ruff check . --exclude .venv,tests --select F,B,S,ASYNC,E9
pip-audit -r requirements.txt
```

---

## Bot Permissions

**This bot requires Administrator.** That is not laziness — it follows from two Discord rules that together leave no alternative.

Every permission change passes **two independent gates**:

1. **Hierarchy** — you may only touch roles positioned _below_ your own highest role. Administrator does **not** override this.
2. **Possession** — you may only change permission bits that **you yourself hold**.

Gate 2 is the binding one. Panic mode's entire job is stripping `administrator` and `manage_guild` from compromised roles — and Gate 2 says a bot cannot remove a permission it does not have. Likewise `/announce` grants `mention_everyone`, which the bot must therefore hold. A bot without Administrator would silently fail to strip the five permissions that matter most, while still reporting success.

```
https://discord.com/api/oauth2/authorize?client_id=YOUR_BOT_ID&permissions=8&scope=bot%20applications.commands
```

**Role position still matters.** Administrator does not beat hierarchy. Place the bot's role directly beneath your cold admin roles and above everything it needs to manage. If `/panic` or `/role` is skipping roles, the fix is moving the bot's role up — not more permissions.

**What Administrator means for your threat model:** the **bot token** becomes the single most valuable secret in the system. Your 2FA system protects against a compromised _user_ — an attacker who phishes an announcer still needs a TOTP code. An attacker with the _token_ bypasses the bot entirely and talks to Discord's API directly, with Administrator. Keep it out of git, out of screenshots, and rotate it on any doubt.

**Hard limits, even with Administrator:**

- The **server owner cannot be touched** — not kicked, banned, or stripped. Discord ignores permission checks for them. If that account is compromised, no bot can help, which is why it should be a cold account that rarely logs in.
- Roles **above** the bot's role cannot be edited.
- **Managed roles** (other bots, the Nitro booster role) can never be edited by anyone.

---

## Emergency Runbook

### The rule

> The **bot** must be in the server. **You** do not.

The DM commands resolve the guild through the bot's own membership, so the global operator can act after being kicked from the server — or having never joined it.

### Setup: a control server

Discord generally requires a shared server before you can DM a bot. Create a **private server containing only you and the bot**. That guarantees DM access can never be severed by removing you from a client's server.

### Commands

Sent as a direct message to the bot, by the `MASTER_USER_ID` account only:

```
panic <guild_id> <6-digit-2fa-code> CONFIRM LOCKDOWN
recover-panic <guild_id> <6-digit-2fa-code>
```

Both are logged to the affected server's own log channel, and `panic` also DMs that server's owner. The operator cannot act invisibly.

### What recovery does and does not restore

|                   |                                                          |
| ----------------- | -------------------------------------------------------- |
| **Restored**      | Role permissions, channel visibility and send overwrites |
| **Not restored**  | Deleted webhooks, bans, deleted scheduled events         |
| **Never touched** | Roles above the bot's role, managed/integration roles    |

Recovery undoes the _lockdown_. It does not undo an attacker's damage — those are different jobs.

### If nothing works

If the bot itself was removed from the server, no DM command can help. Re-invite it, then run `/recover` — the panic backup is stored in the database, not in the guild. This is the reason it's advised to move the bot up top in the role hierarchy so an attacker that gained access through roles beneath it can't kick the bot.

---

## Deployment

### Railway (or any container host)

**Attach a persistent volume.** Container filesystems are ephemeral: without one, `database.db` is wiped on every deploy, and every 2FA registration, guild setup, whitelist, and filter resets to empty.

1. Add a volume, mounted at e.g. `/data`
2. Set `DATABASE_PATH=/data/database.db`
3. Set `BOT_TOKEN`, `MASTER_USER_ID`, and `ENCRYPTION_KEY` as service variables

The symptom of a missing volume is "everyone has to run `/create-2fa` again after re-deploy."

The `Procfile` runs `worker: python bot.py`. Cogs load independently, so one failing cog no longer stops the bot — check startup logs for `[COG] FAILED`.

### Branding per server

The bot's username and avatar are global (set in the Developer Portal). Per server you can set a **nickname** and role colour like any member, and embed colour/footer are configurable per guild in the `guild_branding` table. Full white-label — a different name _and_ avatar per client — requires a separate Discord application per client.

This bot is free to use and open source under the MIT license.  
For custom deployment, configuration, or integration into your Web3 project's Discord server, reach out to the author.

---

## License

[MIT License](LICENSE) — use it, fork it, build on it. Credit stays in the source.

---

## Built By

<div align="center">

### [Nuelverse](https://github.com/Nuelverse)

**Community Builder/Manager · Aspiring Blockchain Developer**

[![GitHub](https://img.shields.io/badge/GitHub-Nuelverse-181717?style=for-the-badge&logo=github&logoColor=white)](https://github.com/Nuelverse)
[![X](https://img.shields.io/badge/X-@nuelverse-000000?style=for-the-badge&logo=x&logoColor=white)](https://x.com/nuelverse)
[![Discord](https://img.shields.io/badge/Discord-nuelverse-5865F2?style=for-the-badge&logo=discord&logoColor=white)](https://discord.com/users/1039501090917457950)
[![Telegram](https://img.shields.io/badge/Telegram-@nuelverse-26A5E4?style=for-the-badge&logo=telegram&logoColor=white)](https://t.me/nuelverse)
[![Email](https://img.shields.io/badge/Email-nuelverse%40proton.me-6D4AFF?style=for-the-badge&logo=protonmail&logoColor=white)](mailto:nuelverse@proton.me)

_If this bot protects your server, consider reaching out._

</div>
