"""
Panic Mode — Emergency server lockdown. BOT OWNER ONLY.

Commands:
  /panic    — Opens a confirmation modal (2FA + typed confirmation phrase).
              Backs up all role permissions and channel overwrites, then locks
              down the entire server.

  /recover  — Bot owner: restore the server from the most recent panic backup.
              Requires 2FA.

DM triggers (for when the bot owner has been kicked from the server):
    panic <guild_id> <6-digit-2fa-code> CONFIRM LOCKDOWN
    recover-panic <guild_id> <6-digit-2fa-code>

WARNING: /panic is destructive and irreversible without /recover.
"""

import discord
from discord.ext import commands
from discord.commands import Option
from datetime import datetime
import db_handler
import two_factor_helper
import permissions
import logger


CONFIRM_PHRASE = "CONFIRM LOCKDOWN"


# ---------------------------------------------------------------------------
# Confirmation modal (2FA + typed phrase for double verification)
# ---------------------------------------------------------------------------

class PanicConfirmModal(discord.ui.Modal):
    def __init__(self, bot, guild: discord.Guild):
        super().__init__(title="PANIC — Confirm Server Lockdown")
        self.bot = bot
        self.guild = guild

        self.add_item(discord.ui.InputText(
            label="Your 2FA Code",
            style=discord.InputTextStyle.short,
            placeholder="6-digit code from your authenticator app",
            min_length=6,
            max_length=6,
            required=True,
        ))
        self.add_item(discord.ui.InputText(
            label=f'Type exactly: {CONFIRM_PHRASE}',
            style=discord.InputTextStyle.short,
            placeholder=CONFIRM_PHRASE,
            min_length=len(CONFIRM_PHRASE),
            max_length=len(CONFIRM_PHRASE) + 5,
            required=True,
        ))

    async def callback(self, interaction: discord.Interaction):
        code_str = self.children[0].value.strip()
        confirm_phrase = self.children[1].value.strip()

        try:
            code = int(code_str)
        except ValueError:
            await interaction.response.send_message("Invalid 2FA code format.", ephemeral=True)
            return

        if not two_factor_helper.verify_code(self.bot.CONN, interaction.user.id, code):
            await interaction.response.send_message("Incorrect 2FA code.", ephemeral=True)
            return

        if confirm_phrase != CONFIRM_PHRASE:
            await interaction.response.send_message(
                f"Confirmation phrase must be exactly: `{CONFIRM_PHRASE}`", ephemeral=True
            )
            return

        await interaction.response.send_message(
            "PANIC LOCKDOWN INITIATED. Locking down the server...", ephemeral=True
        )

        cog = self.bot.cogs.get("Panic")
        if cog:
            await cog._execute_panic(self.guild, interaction.user)


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _strip_dangerous_permissions(perms: discord.Permissions, dangerous: list[str]) -> discord.Permissions:
    new_perms = discord.Permissions(perms.value)
    for perm in dangerous:
        if hasattr(new_perms, perm):
            setattr(new_perms, perm, False)
    return new_perms


# ---------------------------------------------------------------------------
# Cog
# ---------------------------------------------------------------------------

class Panic(commands.Cog):
    def __init__(self, bot):
        self.bot = bot

    # ------------------------------------------------------------------
    # Core lockdown logic
    # ------------------------------------------------------------------

    async def _execute_panic(self, guild: discord.Guild, triggered_by):
        dangerous = self.bot.config.get("panic", {}).get("dangerous_permissions", [])
        audit_reason = f"PANIC LOCKDOWN — triggered by {triggered_by} ({triggered_by.id})"
        bot_member = guild.get_member(self.bot.user.id)
        bot_top_role = bot_member.top_role if bot_member else None

        log_id = db_handler.get_log_channel(self.bot.CONN, guild.id)
        log_ch = self.bot.get_channel(log_id) if log_id else None

        db_handler.clear_panic_backups(self.bot.CONN, guild.id)

        # Phase 1: Strip dangerous permissions from all roles
        role_errors = 0
        for role in guild.roles:
            if role.managed:
                continue
            if bot_top_role and role >= bot_top_role:
                continue
            db_handler.save_panic_role_backup(self.bot.CONN, guild.id, role.id, role.permissions.value)
            new_perms = _strip_dangerous_permissions(role.permissions, dangerous)
            if new_perms.value == role.permissions.value:
                continue
            try:
                await role.edit(permissions=new_perms, reason=audit_reason)
            except (discord.Forbidden, discord.HTTPException):
                role_errors += 1

        await logger.safe_send(log_ch, content=f"PANIC Phase 1: roles stripped. Errors: {role_errors}")

        # Phase 2: Delete all webhooks
        wh_errors = 0
        try:
            webhooks = await guild.webhooks()
            for webhook in webhooks:
                try:
                    await webhook.delete(reason=audit_reason)
                except (discord.Forbidden, discord.HTTPException):
                    wh_errors += 1
        except discord.Forbidden:
            wh_errors = -1

        await logger.safe_send(log_ch, content=f"PANIC Phase 2: webhooks deleted. Errors: {wh_errors}")

        # Phase 3: Delete all scheduled events
        try:
            events = await guild.fetch_scheduled_events()
            for event in events:
                try:
                    await event.delete()
                except (discord.Forbidden, discord.HTTPException):
                    pass
        except Exception as e:
            # Scheduled events are non-critical during a lockdown — log and move on.
            print(f"[panic] Could not clear scheduled events for {guild.id}: {e}")

        # Phase 4: Lock all channels
        channel_errors = 0
        default_role = guild.default_role
        deny_overwrite = discord.PermissionOverwrite(view_channel=False, send_messages=False)

        for channel in guild.channels:
            existing = channel.overwrites_for(default_role)
            db_handler.save_panic_channel_backup(
                self.bot.CONN, guild.id, channel.id,
                existing.pair()[0].value,
                existing.pair()[1].value,
            )
            try:
                await channel.set_permissions(default_role, overwrite=deny_overwrite, reason=audit_reason)
            except (discord.Forbidden, discord.HTTPException):
                channel_errors += 1

        await logger.safe_send(log_ch, content=f"PANIC Phase 3: channels locked. Errors: {channel_errors}")

        db_handler.set_panic_active(self.bot.CONN, guild.id, True)

        # DM the server owner
        try:
            owner = guild.owner or await guild.fetch_member(guild.owner_id)
            if owner:
                await owner.send(
                    f"PANIC LOCKDOWN triggered on **{guild.name}** by **{triggered_by}** "
                    f"at {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC.\n\n"
                    "The server has been locked down. Run `/recover` when it is safe to restore."
                )
        except (discord.Forbidden, discord.HTTPException, AttributeError):
            pass

        embed = discord.Embed(
            title="PANIC LOCKDOWN ACTIVATED",
            color=0xe74c3c,
            timestamp=datetime.utcnow(),
        )
        embed.add_field(name="Triggered By", value=f"{triggered_by.mention} ({triggered_by.id})", inline=False)
        embed.add_field(name="Roles Processed", value=f"{len(guild.roles)} ({role_errors} errors)", inline=True)
        embed.add_field(name="Channels Locked", value=f"{len(guild.channels)} ({channel_errors} errors)", inline=True)
        embed.set_footer(text="Run /recover to restore. Server owner has been DM'd.")
        await logger.safe_send(log_ch, embed=embed)

    # ------------------------------------------------------------------
    # Core restore logic
    # ------------------------------------------------------------------

    async def _execute_recover(self, guild: discord.Guild, triggered_by) -> bool:
        audit_reason = f"PANIC RESTORE — by {triggered_by} ({triggered_by.id})"
        log_id = db_handler.get_log_channel(self.bot.CONN, guild.id)
        log_ch = self.bot.get_channel(log_id) if log_id else None

        role_backups = db_handler.get_panic_role_backups(self.bot.CONN, guild.id)
        channel_backups = db_handler.get_panic_channel_backups(self.bot.CONN, guild.id)

        if not role_backups and not channel_backups:
            return False

        role_errors = 0
        for role_id, perms_value in role_backups:
            role = guild.get_role(role_id)
            if role is None:
                continue
            try:
                await role.edit(permissions=discord.Permissions(perms_value), reason=audit_reason)
            except (discord.Forbidden, discord.HTTPException):
                role_errors += 1

        await logger.safe_send(log_ch, content=f"RECOVER: Roles restored. Errors: {role_errors}")

        default_role = guild.default_role
        channel_errors = 0
        for channel_id, allow_value, deny_value in channel_backups:
            channel = guild.get_channel(channel_id)
            if channel is None:
                continue
            try:
                allow = discord.Permissions(allow_value)
                deny = discord.Permissions(deny_value)
                if allow_value == 0 and deny_value == 0:
                    await channel.set_permissions(default_role, overwrite=None, reason=audit_reason)
                else:
                    overwrite = discord.PermissionOverwrite.from_pair(allow, deny)
                    await channel.set_permissions(default_role, overwrite=overwrite, reason=audit_reason)
            except (discord.Forbidden, discord.HTTPException):
                channel_errors += 1

        await logger.safe_send(log_ch, content=f"RECOVER: Channels restored. Errors: {channel_errors}")

        db_handler.clear_panic_backups(self.bot.CONN, guild.id)
        db_handler.set_panic_active(self.bot.CONN, guild.id, False)

        embed = discord.Embed(
            title="PANIC LOCKDOWN LIFTED",
            color=0x2ecc71,
            timestamp=datetime.utcnow(),
        )
        embed.add_field(name="Restored By", value=f"{triggered_by.mention} ({triggered_by.id})", inline=False)
        embed.add_field(name="Roles Restored", value=f"{len(role_backups)} ({role_errors} errors)", inline=True)
        embed.add_field(name="Channels Restored", value=f"{len(channel_backups)} ({channel_errors} errors)", inline=True)
        embed.set_footer(text="Note: deleted webhooks must be re-added manually.")
        await logger.safe_send(log_ch, embed=embed)
        return True

    # ------------------------------------------------------------------
    # /panic  (bot owner — opens confirmation modal)
    # ------------------------------------------------------------------

    @commands.guild_only()
    @commands.cooldown(1, 10, commands.BucketType.user)
    @commands.slash_command(
        description="[Owner] EMERGENCY: Lock down the entire server. Opens a confirmation modal."
    )
    async def panic(self, ctx: discord.ApplicationContext):
        # Server owner too: it is their server and their emergency. The global
        # operator keeps the DM hatch for when nobody can reach a slash command.
        allowed, err = permissions.check(self.bot, ctx, 'owner')
        if not allowed:
            await ctx.respond(err, ephemeral=True)
            return

        ok, err2 = permissions.guild_required(self.bot, ctx)
        if not ok:
            await ctx.respond(err2, ephemeral=True)
            return

        if db_handler.get_panic_active(self.bot.CONN, ctx.guild.id):
            await ctx.respond(
                "Server is already in panic lockdown. Run `/recover` to restore.",
                ephemeral=True
            )
            return

        modal = PanicConfirmModal(self.bot, ctx.guild)
        await ctx.send_modal(modal)

    # ------------------------------------------------------------------
    # /recover  (bot owner + 2FA — restore from backup)
    # ------------------------------------------------------------------

    @commands.guild_only()
    @commands.cooldown(1, 10, commands.BucketType.user)
    @commands.slash_command(
        description="[Owner] Recover server permissions from the most recent backup. Requires 2FA."
    )
    async def recover(self, ctx: discord.ApplicationContext,
                      code: Option(int, "Your 6-digit 2FA code", required=True)):
        allowed, err = permissions.check(self.bot, ctx, 'owner')
        if not allowed:
            await ctx.respond(err, ephemeral=True)
            return

        ok, err2 = permissions.guild_required(self.bot, ctx)
        if not ok:
            await ctx.respond(err2, ephemeral=True)
            return

        if not two_factor_helper.verify_code(self.bot.CONN, ctx.author.id, code):
            await ctx.respond("Incorrect 2FA code.", ephemeral=True)
            return

        if not db_handler.get_panic_active(self.bot.CONN, ctx.guild.id):
            await ctx.respond("The server is not currently in panic lockdown.", ephemeral=True)
            return

        await ctx.respond("Restoring server permissions...", ephemeral=True)
        restored = await self._execute_recover(ctx.guild, ctx.author)

        if not restored:
            await ctx.respond(
                "No backup data found. The server state cannot be automatically restored. "
                "Manually reconfigure role permissions and channel overwrites.",
                ephemeral=True
            )

    # ------------------------------------------------------------------
    # DM trigger: panic <guild_id> <code>
    # ------------------------------------------------------------------

    @commands.Cog.listener("on_message")
    async def on_dm_panic(self, message: discord.Message):
        if message.guild is not None or message.author.bot:
            return
        if message.author.id != self.bot.master_user:
            return

        content = message.content.strip()
        if not content.lower().startswith("panic "):
            return

        parts = content.split()
        # Expected: panic <guild_id> <code> CONFIRM LOCKDOWN  (5 tokens)
        if len(parts) < 5:
            await message.channel.send(
                f"Format: `panic <guild_id> <6-digit-2fa-code> {CONFIRM_PHRASE}`"
            )
            return

        guild_id_str = parts[1]
        code_str = parts[2]
        confirm = " ".join(parts[3:])
        try:
            guild_id = int(guild_id_str)
            code = int(code_str)
        except ValueError:
            await message.channel.send("Invalid guild ID or code format.")
            return

        guild = self.bot.get_guild(guild_id)
        if guild is None:
            await message.channel.send("Bot is not in that server or invalid guild ID.")
            return

        if not db_handler.check_guild(self.bot.CONN, guild_id):
            await message.channel.send("That server is not set up with this bot.")
            return

        if confirm != CONFIRM_PHRASE:
            await message.channel.send(
                f"Confirmation phrase must be exactly: `{CONFIRM_PHRASE}`"
            )
            return

        if not two_factor_helper.verify_code(self.bot.CONN, message.author.id, code):
            await message.channel.send("Incorrect 2FA code.")
            return

        if db_handler.get_panic_active(self.bot.CONN, guild_id):
            await message.channel.send("Server is already in panic lockdown.")
            return

        await message.channel.send(f"Initiating panic lockdown for **{guild.name}**...")
        await self._execute_panic(guild, message.author)
        await message.channel.send(
            "Panic lockdown complete.\n"
            f"To restore later, DM: `recover-panic {guild_id} <6-digit-2fa-code>`"
        )

    # ------------------------------------------------------------------
    # DM trigger: recover-panic <guild_id> <code>
    # ------------------------------------------------------------------

    @commands.Cog.listener("on_message")
    async def on_dm_recover_panic(self, message: discord.Message):
        """
        Restore a locked-down server from a DM.

        The documented reason to trigger panic by DM is that the owner was
        kicked from the server — but /recover is guild-only, so without this
        the escape hatch had no exit and the server stayed locked.
        """
        if message.guild is not None or message.author.bot:
            return
        if message.author.id != self.bot.master_user:
            return

        content = message.content.strip()
        if not content.lower().startswith("recover-panic "):
            return

        parts = content.split()
        if len(parts) < 3:
            await message.channel.send("Format: `recover-panic <guild_id> <6-digit-2fa-code>`")
            return

        try:
            guild_id = int(parts[1])
            code = int(parts[2])
        except ValueError:
            await message.channel.send("Invalid guild ID or code format.")
            return

        guild = self.bot.get_guild(guild_id)
        if guild is None:
            await message.channel.send("Bot is not in that server or invalid guild ID.")
            return

        if not db_handler.check_guild(self.bot.CONN, guild_id):
            await message.channel.send("That server is not set up with this bot.")
            return

        if not two_factor_helper.verify_code(self.bot.CONN, message.author.id, code):
            await message.channel.send("Incorrect 2FA code.")
            return

        if not db_handler.get_panic_active(self.bot.CONN, guild_id):
            await message.channel.send("That server is not currently in panic lockdown.")
            return

        await message.channel.send(f"Restoring **{guild.name}** from the most recent backup...")
        restored = await self._execute_recover(guild, message.author)
        if restored:
            await message.channel.send(
                "Recovery complete. Note: deleted webhooks must be re-added manually."
            )
        else:
            await message.channel.send(
                "No backup data found — role permissions and channel overwrites "
                "must be reconfigured manually."
            )


def setup(bot):
    bot.add_cog(Panic(bot))
