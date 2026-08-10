"""
Core — 2FA registration, verification, and account recovery.

Commands:
  /create-2fa   — Generate a TOTP QR code (available to registered users,
                  server owners, and bot owner).
  /verify       — Confirm the TOTP pairing.
  /reset-user   — Bot owner or server owner: wipe a user's 2FA so they can re-register.

Recovery model:
  There is no self-service recovery. Losing an authenticator requires an owner
  to run /reset-user, which is written to the audit log, after which the user
  re-enrols with /create-2fa.

  Single-use backup codes used to fill this role and were removed. Shown once
  in a Discord message, they were habitually screenshotted into saved messages
  or a notes app — so an attacker who phished the Discord account also found
  the codes, wiped the victim's 2FA over DM, paired their own authenticator,
  and inherited the keycard silently. Re-issuing access through a person is
  slower and strictly safer.
"""

import asyncio
import os

import discord
from discord.ext import commands, tasks
from discord.commands import Option
import db_handler
import two_factor_helper
import permissions
import logger


class Core(commands.Cog):
    def __init__(self, bot):
        self.bot = bot
        self.delete_pngs.start()

    def cog_unload(self):
        self.delete_pngs.cancel()

    # ------------------------------------------------------------------
    # Background task: purge QR code PNGs every minute
    # ------------------------------------------------------------------

    @tasks.loop(minutes=1)
    async def delete_pngs(self):
        """
        Purge stray QR PNGs.

        New setups render the QR straight to memory and never write it to disk,
        so this only sweeps files left behind by older versions. Runs in a
        worker thread because filesystem calls block the event loop.
        """
        await asyncio.to_thread(self._purge_png_files)

    @staticmethod
    def _purge_png_files():
        data_dir = './data/'
        if not os.path.isdir(data_dir):
            return
        for f in os.listdir(data_dir):
            if f.endswith('.png'):
                try:
                    os.remove(os.path.join(data_dir, f))
                except OSError:
                    pass

    @delete_pngs.before_loop
    async def before_delete_pngs(self):
        await self.bot.wait_until_ready()

    # ------------------------------------------------------------------
    # /create-2fa
    # ------------------------------------------------------------------

    @commands.guild_only()
    @commands.cooldown(1, 10, commands.BucketType.user)
    @commands.slash_command(
        name="create-2fa",
        description="Set up 2FA for your account. Required before using your designated commands."
    )
    async def create_2fa(self, ctx: discord.ApplicationContext):
        if not permissions.can_setup_2fa(self.bot, ctx):
            await ctx.respond(
                "You are not registered in this server. "
                "Contact the server owner or bot owner to be added as an announcer or link manager.",
                ephemeral=True
            )
            return

        user_id = ctx.author.id

        if db_handler.check_user(self.bot.CONN, user_id):
            if db_handler.check_verified(self.bot.CONN, user_id) == 1:
                await ctx.respond(
                    "You already have 2FA set up. If you lost access to your authenticator, "
                    "ask a server owner to run `/reset-user` for you, then run `/create-2fa` again.",
                    ephemeral=True
                )
            else:
                await ctx.respond(
                    "You have a pending 2FA setup. Run `/verify code:<6-digit-code>` to complete it.",
                    ephemeral=True
                )
            return

        qr_buffer, secret = two_factor_helper.setup_and_get_path(ctx, self.bot.CONN)

        await ctx.respond(
            "**2FA Setup — Security Bot**\n\n"
            "1. Open **Authy** or **Google Authenticator** — never scan QR codes with Discord mobile.\n"
            "2. Scan the QR code below, or add manually as a **Time-based OTP** using this key:\n"
            f"```{secret}```\n"
            "3. Run `/verify code:<6-digit-code>` to confirm pairing.\n\n"
            "**Back up your authenticator now.** Use an app with its own encrypted "
            "backup (Authy, 1Password, Bitwarden), or add the key above to a second "
            "device. There are no recovery codes — if you lose your authenticator, a "
            "server owner must run `/reset-user` before you can pair a new one.\n\n"
            "Note: each 2FA code can only be used once. If you run two commands "
            "back to back, wait for your app to show a fresh code.",
            file=discord.File(qr_buffer, filename="2fa-qr.png"),
            ephemeral=True
        )

        await logger.log_action(
            self.bot, ctx.guild, "2FA Setup Initiated", ctx.author,
            details={"Status": "QR code generated, awaiting /verify"},
            level='info'
        )

    # ------------------------------------------------------------------
    # /verify
    # ------------------------------------------------------------------

    @commands.guild_only()
    @commands.cooldown(1, 5, commands.BucketType.user)
    @commands.slash_command(description="Confirm your 2FA pairing with a 6-digit code.")
    async def verify(self, ctx: discord.ApplicationContext,
                     code: Option(int, "6-digit code from your authenticator app", required=True)):
        user_id = ctx.author.id

        if not db_handler.check_user(self.bot.CONN, user_id):
            await ctx.respond("Run `/create-2fa` first to start setup.", ephemeral=True)
            return

        if db_handler.check_verified(self.bot.CONN, user_id) == 1:
            await ctx.respond("Your 2FA is already verified.", ephemeral=True)
            return

        if two_factor_helper.verify_code(self.bot.CONN, user_id, code):
            db_handler.verify(self.bot.CONN, user_id)
            await ctx.respond(
                "2FA verified. You can now use all commands assigned to your role.",
                ephemeral=True
            )
            await logger.log_action(
                self.bot, ctx.guild, "2FA Verified", ctx.author,
                details={"Status": "TOTP pairing confirmed"},
                level='success'
            )
        else:
            await ctx.respond(
                "Incorrect code. Check your authenticator app (codes expire every 30 seconds) "
                "and try again.",
                ephemeral=True
            )

    # ------------------------------------------------------------------
    # /reset-user  (bot owner or server owner + 2FA)
    # ------------------------------------------------------------------

    @commands.guild_only()
    @commands.cooldown(1, 5, commands.BucketType.user)
    @commands.slash_command(
        name="reset-user",
        description="[Owner] Reset a user's 2FA so they can re-register. Requires your 2FA code."
    )
    async def reset_user(self, ctx: discord.ApplicationContext,
                         member: Option(discord.Member, "Member to reset"),
                         code: Option(int, "Your 6-digit 2FA code", required=True)):
        allowed, err = permissions.check(self.bot, ctx, 'owner')
        if not allowed:
            await ctx.respond(err, ephemeral=True)
            return

        if not two_factor_helper.verify_code(self.bot.CONN, ctx.author.id, code):
            await ctx.respond("Incorrect 2FA code.", ephemeral=True)
            return

        if not db_handler.check_user(self.bot.CONN, member.id):
            await ctx.respond(f"{member.mention} has no 2FA account to reset.", ephemeral=True)
            return

        db_handler.delete_user(self.bot.CONN, member.id)
        await ctx.respond(
            f"{member.mention}'s 2FA has been reset. They must run `/create-2fa` again.",
            ephemeral=True
        )
        try:
            await member.send(
                f"Your 2FA for **{ctx.guild.name}** has been reset by {ctx.author}. "
                "Please run `/create-2fa` in the server to re-register."
            )
        except (discord.Forbidden, discord.HTTPException):
            pass

        await logger.log_action(
            self.bot, ctx.guild, "2FA Reset", ctx.author,
            details={"Target": f"{member} ({member.id})", "Action": "2FA account deleted, re-registration required"},
            level='warning'
        )

def setup(bot):
    bot.add_cog(Core(bot))
