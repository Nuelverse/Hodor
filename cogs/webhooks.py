import discord
from discord.ext import commands, tasks
from discord.commands import Option
from datetime import datetime, timedelta, timezone
import time
import db_handler
import two_factor_helper
import permissions
import logger


def _utcnow_naive() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


class Webhooks(commands.Cog):
    def __init__(self, bot):
        self.bot = bot
        self.check_temp_disables.start()

    def cog_unload(self):
        self.check_temp_disables.cancel()

    # Background task: re-enable protection when 30-min window expires

    @tasks.loop(minutes=1)
    async def check_temp_disables(self):
        for guild in self.bot.guilds:
            if not db_handler.check_guild(self.bot.CONN, guild.id):
                continue
            expires_str = db_handler.get_webhook_temp_disable(self.bot.CONN, guild.id)
            if expires_str is None:
                continue
            try:
                expires_at = datetime.fromisoformat(expires_str)
            except ValueError:
                db_handler.clear_webhook_temp_disable(self.bot.CONN, guild.id)
                continue
            if _utcnow_naive() >= expires_at:
                db_handler.clear_webhook_temp_disable(self.bot.CONN, guild.id)
                log_ch = logger.get_log_channel(self.bot, guild)
                embed = discord.Embed(
                    title="Webhook Protection Re-enabled",
                    description="The 30-minute webhook allow window has expired. Protection is active again.",
                    color=0x2ecc71,
                    timestamp=_utcnow_naive()
                )
                await logger.safe_send(log_ch, embed=embed)

    @check_temp_disables.before_loop
    async def before_check(self):
        await self.bot.wait_until_ready()

    # Helpers

    def _build_log_embed(self, color: int, user, channel, action: str) -> discord.Embed:
        embed = discord.Embed(title="Webhook Event", color=color, timestamp=_utcnow_naive())
        embed.add_field(
            name="Created By",
            value=f"{user.name} ({user.id})" if user else "Unknown",
            inline=False
        )
        embed.add_field(name="Channel", value=channel.mention, inline=False)
        embed.add_field(name="Action", value=action, inline=False)
        embed.set_footer(text=f"Guild: {channel.guild.name}")
        return embed

    # on_webhooks_update - core protection listener

    @commands.Cog.listener("on_webhooks_update")
    async def on_webhooks_update(self, channel: discord.abc.GuildChannel):
        guild = channel.guild

        if not db_handler.check_guild(self.bot.CONN, guild.id):
            return

        # Check if permanently disabled
        if not db_handler.check_webhook(self.bot.CONN, guild.id):
            return

        # Check if temporarily disabled (allow window active)
        expires_str = db_handler.get_webhook_temp_disable(self.bot.CONN, guild.id)
        if expires_str:
            try:
                if _utcnow_naive() < datetime.fromisoformat(expires_str):
                    log_ch = logger.get_log_channel(self.bot, guild)
                    await logger.safe_send(log_ch, embed=self._build_log_embed(
                        0x3498db, None, channel,
                        "Webhook created during allow window — allowed."
                    ))
                    return
            except ValueError:
                pass

        log_ch = logger.get_log_channel(self.bot, guild)

        try:
            webhooks = await channel.webhooks()
        except discord.Forbidden:
            await logger.safe_send(log_ch, embed=self._build_log_embed(
                0xe74c3c, None, channel,
                "Could not fetch webhooks — missing permissions."
            ))
            return

        if not webhooks:
            return

        # Examine EVERY webhook created inside the window, not just webhooks[-1].
        # Discord does not guarantee this list is ordered by creation time, and
        # an attacker creating several webhooks in one burst previously had all
        # but one survive.
        cutoff = time.time() - 120
        verified_bots_allowed = db_handler.check_verified_bots(self.bot.CONN, guild.id)

        recent_webhooks = [
            wh for wh in webhooks
            if wh.created_at is not None
            and wh.created_at.timestamp() >= cutoff
            # Ignore channel follows (Discord-native, not user-created)
            and wh.type != discord.WebhookType.channel_follower
        ]

        for webhook in recent_webhooks:
            # Allow verified-bot webhooks if the bypass is enabled
            if verified_bots_allowed and webhook.user and webhook.user.public_flags.verified_bot:
                await logger.safe_send(log_ch, embed=self._build_log_embed(
                    0x2ecc71, webhook.user, channel,
                    "Verified bot webhook — allowed (bypass enabled)."
                ))
                continue

            try:
                await webhook.delete(reason="Webhook protection enabled.")
            except discord.NotFound:
                continue  # Already gone.
            except (discord.Forbidden, discord.HTTPException):
                await logger.safe_send(log_ch, embed=self._build_log_embed(
                    0xe74c3c, webhook.user if webhook.user else None, channel,
                    "Failed to delete webhook — missing permissions."
                ))
                continue

            await logger.safe_send(log_ch, embed=self._build_log_embed(
                0xf1c40f,
                webhook.user if webhook.user else None,
                channel,
                f"Unauthorized webhook deleted (ID: {webhook.id})."
            ))

    # /allow-webhook  (bot owner + 2FA)

    @commands.guild_only()
    @commands.slash_command(
        name="allow-webhook",
        description="[Owner] Temporarily disable webhook protection for 30 minutes. Requires 2FA."
    )
    async def allow_webhook(self, ctx: discord.ApplicationContext,
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

        expires_at = _utcnow_naive() + timedelta(minutes=30)
        db_handler.set_webhook_temp_disable(
            self.bot.CONN, ctx.guild.id, ctx.author.id, expires_at.isoformat()
        )

        await ctx.respond(
            f"Webhook protection suspended for **30 minutes** (until "
            f"<t:{int(expires_at.timestamp())}:t>). "
            "Add your webhook(s) now. Protection will resume automatically.",
            ephemeral=True
        )
        await logger.log_action(
            self.bot, ctx.guild, "Webhook Protection Temporarily Disabled", ctx.author,
            details={
                "Duration": "30 minutes",
                "Expires": f"<t:{int(expires_at.timestamp())}:f>",
            },
            level='warning'
        )


def setup(bot):
    bot.add_cog(Webhooks(bot))
