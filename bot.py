import asyncio
import os
import sys
import time
from collections import OrderedDict

import discord
from discord.ext import commands
import json
from dotenv import load_dotenv
import db_handler
import two_factor_helper

# py-cord calls asyncio.get_event_loop() at init time, which raises on Python 3.10+
# when no loop exists yet. Create one explicitly before instantiating the bot.
asyncio.set_event_loop(asyncio.new_event_loop())

load_dotenv()

with open('./config.json') as f:
    config = json.load(f)

COGS = [
    'cogs.core',           # 2FA setup, verify, reset-user
    'cogs.link_filter',    # Link scanning + allow-link, remove-link, toggle-linkfilter
    'cogs.webhooks',       # Webhook protection + allow-webhook
    'cogs.panic',          # /panic, /recover, DM trigger
    'cogs.announcements',  # /announce
    'cogs.admin',          # add/remove managers, setup-guild, list, set-logs
    'cogs.moderation',     # role, bulk-role, export, channel utilities
    'cogs.audit',          # Message deletion/edit logging
    'cogs.embeds',         # /embed send, edit, delete, list
    'cogs.name_filter',    # /name-filter add, import, remove, list, test, set-action, cleanse
    'cogs.verification',   # /verify-setup, verify-panel, verify-toggle, verify-status
]


class BoundedIdSet:
    """
    A set of message IDs with a hard size cap.

    The link filter marks a message ID before deleting it so the audit cog can
    suppress a duplicate log entry. When the delete fails (missing permissions,
    message already gone) nothing ever removes the ID, so a plain set grew
    without bound for the lifetime of the process. Oldest entries are evicted
    once the cap is reached.
    """

    def __init__(self, maxlen: int = 2048):
        self._data = OrderedDict()
        self._maxlen = maxlen

    def add(self, item):
        self._data[item] = None
        self._data.move_to_end(item)
        while len(self._data) > self._maxlen:
            self._data.popitem(last=False)

    def discard(self, item):
        self._data.pop(item, None)

    def __contains__(self, item):
        return item in self._data

    def __len__(self):
        return len(self._data)


class SecurityBot(discord.Bot):
    def __init__(self, master_user: int):
        intents = discord.Intents.default()
        intents.members = True
        intents.guilds = True
        intents.webhooks = True
        intents.scheduled_events = True
        intents.messages = True
        intents.message_content = True  # Privileged — must be enabled in Dev Portal
        debug_guild = int(os.getenv('DEBUG_GUILD_ID', 0)) or None
        super().__init__(intents=intents, debug_guilds=[debug_guild] if debug_guild else None)
        self.config = config
        self.master_user = master_user
        self.CONN = None
        # Message IDs deleted by the link filter — suppresses audit double-log
        self.deleted_by_filter = BoundedIdSet()

    async def on_ready(self):
        # Ensure the data directory exists (legacy QR files, exports)
        os.makedirs('./data', exist_ok=True)

        if self.CONN is None:
            self.CONN = db_handler.startup_db()
            if self.CONN is None:
                print("FATAL: Could not connect to database. Shutting down.")
                await self.close()
                return
            # Encrypt any TOTP secrets still stored in plaintext (no-op without
            # ENCRYPTION_KEY, and safe to run on every start).
            two_factor_helper.migrate_plaintext_secrets(self.CONN)

        print(f'Logged in as {self.user} (ID: {self.user.id})')
        print(f'Guilds: {len(self.guilds)}')
        print(f'Master User ID: {self.master_user}')
        if not two_factor_helper.encryption_enabled():
            print('2FA secret encryption: DISABLED (set ENCRYPTION_KEY in .env)')
        else:
            print('2FA secret encryption: enabled')
        print('----------------------------------')


def _load_master_user() -> int:
    """Read MASTER_USER_ID with a clear error instead of a bare TypeError."""
    raw = os.getenv('MASTER_USER_ID', '').strip()
    if not raw:
        print("FATAL: MASTER_USER_ID is not set in .env — the bot has no owner.")
        sys.exit(1)
    try:
        return int(raw)
    except ValueError:
        print(f"FATAL: MASTER_USER_ID must be a numeric Discord user ID, got {raw!r}.")
        sys.exit(1)


bot = SecurityBot(_load_master_user())

# Load each cog independently. A single import error (e.g. a missing optional
# dependency like openpyxl) previously propagated out of this loop and stopped
# the whole bot from starting, taking every unrelated protection down with it.
_failed_cogs = []
for cog in COGS:
    try:
        bot.load_extension(cog)
    except Exception as e:
        _failed_cogs.append(cog)
        print(f"[COG] FAILED to load {cog}: {type(e).__name__}: {e}")

if _failed_cogs:
    print(f"[COG] {len(_failed_cogs)} cog(s) failed to load: {', '.join(_failed_cogs)}")
    print("[COG] The bot will start without them. Fix the errors above and restart.")


@bot.event
async def on_application_command_error(ctx: discord.ApplicationContext, error: discord.DiscordException):
    if isinstance(error, commands.CommandOnCooldown):
        await ctx.respond(
            f"This command is on cooldown. Try again in **{error.retry_after:.0f}s**.",
            ephemeral=True
        )
    elif isinstance(error, commands.BotMissingPermissions):
        await ctx.respond("I am missing permissions to do that.", ephemeral=True)
    elif isinstance(error, commands.MissingPermissions):
        await ctx.respond("You do not have permission to use this command.", ephemeral=True)
    elif isinstance(error, commands.NoPrivateMessage):
        await ctx.respond("This command can only be used in a server.", ephemeral=True)
    else:
        print(f"[ERROR] Unhandled error in /{ctx.command}: {type(error).__name__}: {error}")
        try:
            await ctx.respond("An unexpected error occurred. Please try again.", ephemeral=True)
        except Exception as e:
            # The interaction may already be expired or answered; nothing to do.
            print(f"[ERROR] Could not deliver error response: {type(e).__name__}: {e}")


if __name__ == '__main__':
    token = os.getenv('BOT_TOKEN')
    if not token:
        print("FATAL: BOT_TOKEN not set in .env")
        sys.exit(1)

    try:
        bot.run(token)
    except discord.errors.HTTPException as e:
        if e.status == 429:
            # Do NOT retry bot.run() in a loop: run() closes its event loop on
            # exit (_cleanup_loop), so a second call fails with
            # "Event loop is closed" rather than reconnecting. Back off, then
            # exit non-zero and let the process supervisor (Procfile / systemd
            # / Docker restart policy) start a fresh process.
            wait = 60
            print(f"[FATAL] Rate limited by Discord on startup (HTTP 429). "
                  f"Sleeping {wait}s, then exiting so the supervisor restarts a clean process.")
            time.sleep(wait)
            sys.exit(1)
        raise
