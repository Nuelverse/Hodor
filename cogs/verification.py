import asyncio
import time

import discord
from discord.ext import commands
from discord.commands import Option

import captcha as captcha_lib
import db_handler
import logger
import permissions
import two_factor_helper


PANEL_BUTTON_ID = "hodor:verify_panel"
LEGACY_PANEL_BUTTON_IDS = ("discord_shield:verify_panel",)

CAPTCHA_TTL = 180           # seconds a challenge stays valid
MIN_SOLVE_SECONDS = 2.5     # faster than this is not a human pressing buttons
MAX_ATTEMPTS = 5            # failed attempts before cooldown
ATTEMPT_WINDOW = 600        # cooldown window, seconds

ISSUE_COOLDOWN = 8
_MAX_CONCURRENT_RENDERS = 4
_RENDER_SLOTS = asyncio.Semaphore(_MAX_CONCURRENT_RENDERS)


class _Session:
    """One in-flight captcha challenge."""

    __slots__ = ("answer", "entered", "expires_at", "started_at")

    def __init__(self, answer: str):
        self.answer = answer
        self.entered = ""
        self.started_at = time.monotonic()
        self.expires_at = self.started_at + CAPTCHA_TTL

    @property
    def expired(self) -> bool:
        return time.monotonic() > self.expires_at

    @property
    def length(self) -> int:
        return len(self.answer)


# Keypad buttons

class _DigitButton(discord.ui.Button):
    def __init__(self, digit: str, row: int):
        super().__init__(label=digit, style=discord.ButtonStyle.primary, row=row)
        self.digit = digit

    async def callback(self, interaction: discord.Interaction):
        await self.view.cog.on_digit(interaction, self.digit)


class _ClearButton(discord.ui.Button):
    def __init__(self, row: int):
        super().__init__(label="Clear", style=discord.ButtonStyle.danger, row=row)

    async def callback(self, interaction: discord.Interaction):
        await self.view.cog.on_clear(interaction)


class _SubmitButton(discord.ui.Button):
    def __init__(self, row: int):
        super().__init__(label="Submit", style=discord.ButtonStyle.success, row=row)

    async def callback(self, interaction: discord.Interaction):
        await self.view.cog.on_submit(interaction)


class CaptchaKeypadView(discord.ui.View):
    """
    Per-challenge keypad. Not persistent: it belongs to one ephemeral message
    and dies with the session, which is what we want.
    """

    def __init__(self, cog):
        super().__init__(timeout=CAPTCHA_TTL)
        self.cog = cog
        for idx, digit in enumerate("123456789"):
            self.add_item(_DigitButton(digit, row=idx // 3))
        self.add_item(_ClearButton(row=3))
        self.add_item(_DigitButton("0", row=3))
        self.add_item(_SubmitButton(row=3))


# Persistent panel

class VerifyPanelView(discord.ui.View):
    """The permanent [Verify] button. Must survive restarts, hence timeout=None."""

    def __init__(self, cog, custom_id: str = PANEL_BUTTON_ID):
        super().__init__(timeout=None)
        self.cog = cog
        button = discord.ui.Button(
            label="Verify",
            style=discord.ButtonStyle.primary,
            custom_id=custom_id,
        )
        button.callback = self._on_click
        self.add_item(button)

    async def _on_click(self, interaction: discord.Interaction):
        await self.cog.on_panel_click(interaction)


# Cog

class Verification(commands.Cog):
    def __init__(self, bot):
        self.bot = bot
        # (guild_id, user_id) -> _Session
        self._sessions: dict[tuple[int, int], _Session] = {}
        # (guild_id, user_id) -> [failed attempt timestamps]
        self._attempts: dict[tuple[int, int], list[float]] = {}
        # (guild_id, user_id) -> monotonic time a challenge was last issued
        self._last_issued: dict[tuple[int, int], float] = {}
        self._view_registered = False

    # Startup - re-register the persistent view

    @commands.Cog.listener()
    async def on_ready(self):
        if self._view_registered:
            return
        self._view_registered = True
        self.bot.add_view(VerifyPanelView(self))
        for legacy_id in LEGACY_PANEL_BUTTON_IDS:
            self.bot.add_view(VerifyPanelView(self, custom_id=legacy_id))
        configured = db_handler.get_all_verification_configs(self.bot.CONN)
        if configured:
            print(f"[verify] Persistent panel re-registered for {len(configured)} guild(s).")

    # Helpers

    def _rate_limited(self, key) -> bool:
        now = time.monotonic()
        recent = [t for t in self._attempts.get(key, []) if now - t < ATTEMPT_WINDOW]
        self._attempts[key] = recent
        return len(recent) >= MAX_ATTEMPTS

    def _record_failure(self, key):
        self._attempts.setdefault(key, []).append(time.monotonic())

    def _prune_sessions(self):
        """Drop expired sessions and stale bookkeeping after a raid."""
        for key in [k for k, s in self._sessions.items() if s.expired]:
            self._sessions.pop(key, None)
        now = time.monotonic()
        for key in [k for k, t in self._last_issued.items()
                    if now - t > max(ISSUE_COOLDOWN, CAPTCHA_TTL)]:
            self._last_issued.pop(key, None)

    @staticmethod
    def _progress(session: _Session) -> str:
        filled = session.entered
        remaining = "▮" * (session.length - len(filled))
        return (f"Your answer: **{filled}**{remaining}  "
                f"({len(filled)}/{session.length})")

    def _brand_color(self, guild_id: int) -> int:
        return db_handler.get_guild_branding(self.bot.CONN, guild_id)['color']

    def _join_log_channel(self, guild, cfg=None):
        
        if cfg is None:
            cfg = db_handler.get_verification_config(self.bot.CONN, guild.id)
        if not cfg or not cfg.get('log_channel_id'):
            return None
        return self.bot.get_channel(cfg['log_channel_id'])

    # Panel click - issue a challenge

    async def on_panel_click(self, interaction: discord.Interaction):
        guild = interaction.guild
        member = interaction.user
        if guild is None:
            return

        cfg = db_handler.get_verification_config(self.bot.CONN, guild.id)
        if not cfg or not cfg['enabled']:
            await interaction.response.send_message(
                "Verification is not currently enabled in this server.", ephemeral=True)
            return

        role = guild.get_role(cfg['role_id'])
        if role is None:
            await interaction.response.send_message(
                "The verified role no longer exists. Please alert a server admin.",
                ephemeral=True)
            return

        if role in getattr(member, "roles", []):
            await interaction.response.send_message(
                "You are already verified.", ephemeral=True)
            return

        # Layer 1 - account age
        min_age_hours = cfg['min_account_age'] or 0
        if min_age_hours:
            age_hours = (discord.utils.utcnow() - member.created_at).total_seconds() / 3600
            if age_hours < min_age_hours:
                wait_h = int(min_age_hours - age_hours) + 1
                await interaction.response.send_message(
                    f"This server requires Discord accounts to be at least "
                    f"**{min_age_hours} hour(s)** old before verifying.\n"
                    f"Please try again in about **{wait_h} hour(s)**.",
                    ephemeral=True)
                # Worth logging: a cluster of these is one of the clearest
                # raid signals you get, since raid accounts are usually hours old.
                await logger.log_action(
                    self.bot, guild, "Verification Blocked — Account Too New", member,
                    details={
                        "Member":      f"{member.mention} — `{member}` (`{member.id}`)",
                        "Account Age": f"<t:{int(member.created_at.timestamp())}:R>",
                        "Requirement": f"{min_age_hours} hour(s) minimum",
                        "Action":      "Verification refused — no role granted",
                    },
                    level='warning',
                    channel=self._join_log_channel(guild, cfg),
                )
                return

        key = (guild.id, member.id)
        if self._rate_limited(key):
            await interaction.response.send_message(
                "Too many failed attempts. Please wait a few minutes and try again.",
                ephemeral=True)
            await logger.log_action(
                self.bot, guild, "Verification Blocked — Too Many Attempts", member,
                details={
                    "Member":      f"{member.mention} — `{member}` (`{member.id}`)",
                    "Account Age": f"<t:{int(member.created_at.timestamp())}:R>",
                    "Attempts":    f"{MAX_ATTEMPTS} failed within {ATTEMPT_WINDOW // 60} minutes",
                    "Action":      "Cooldown applied — no role granted",
                },
                level='warning',
                channel=self._join_log_channel(guild, cfg),
            )
            return

        # Throttle issuance, not just failures - see ISSUE_COOLDOWN.
        last_issued = self._last_issued.get(key, 0.0)
        wait = ISSUE_COOLDOWN - (time.monotonic() - last_issued)
        if wait > 0:
            await interaction.response.send_message(
                f"Please wait {int(wait) + 1}s before requesting another captcha.",
                ephemeral=True)
            return
        self._last_issued[key] = time.monotonic()

        self._prune_sessions()

        await interaction.response.defer(ephemeral=True)

        async with _RENDER_SLOTS:
            buffer, answer = await asyncio.to_thread(captcha_lib.generate)

        session = _Session(answer)
        self._sessions[key] = session

        await interaction.followup.send(
            content=(
                "**Solve the maths problems in the image below.**\n"
                "Enter the answers in order using the keypad, then press Submit.\n\n"
                f"{self._progress(session)}"
            ),
            file=discord.File(buffer, filename="captcha.png"),
            view=CaptchaKeypadView(self),
            ephemeral=True,
        )

    # Keypad handlers

    async def _active_session(self, interaction: discord.Interaction):
        key = (interaction.guild_id, interaction.user.id)
        session = self._sessions.get(key)
        if session is None or session.expired:
            self._sessions.pop(key, None)
            await interaction.response.edit_message(
                content="Captcha expired or not found. Press **Verify** in the channel to try again.",
                view=None,
            )
            return None, key
        return session, key

    async def on_digit(self, interaction: discord.Interaction, digit: str):
        session, _ = await self._active_session(interaction)
        if session is None:
            return
        if len(session.entered) >= session.length:
            await interaction.response.edit_message(
                content=(f"{self._progress(session)}\n"
                         "All digits entered — press **Submit**, or **Clear** to start over."),
            )
            return
        session.entered += digit
        await interaction.response.edit_message(content=(
            "**Solve the maths problems in the image below.**\n"
            "Enter the answers in order using the keypad, then press Submit.\n\n"
            f"{self._progress(session)}"
        ))

    async def on_clear(self, interaction: discord.Interaction):
        session, _ = await self._active_session(interaction)
        if session is None:
            return
        session.entered = ""
        await interaction.response.edit_message(content=(
            "**Solve the maths problems in the image below.**\n"
            "Enter the answers in order using the keypad, then press Submit.\n\n"
            f"{self._progress(session)}"
        ))

    async def on_submit(self, interaction: discord.Interaction):
        session, key = await self._active_session(interaction)
        if session is None:
            return

        guild = interaction.guild
        member = interaction.user
        elapsed = time.monotonic() - session.started_at

        if len(session.entered) < session.length:
            await interaction.response.edit_message(content=(
                f"{self._progress(session)}\n"
                f"Enter all **{session.length}** digits before submitting."
            ))
            return

        self._sessions.pop(key, None)

        # Layer 3 - nobody presses seven buttons this fast
        if elapsed < MIN_SOLVE_SECONDS:
            self._record_failure(key)
            await interaction.response.edit_message(
                content="That was submitted too quickly to be genuine. "
                        "Press **Verify** in the channel to try again.",
                view=None,
            )
            return

        if session.entered != session.answer:
            self._record_failure(key)
            await interaction.response.edit_message(
                content="Incorrect answer. Press **Verify** in the channel to try again.",
                view=None,
            )
            return

        # Success
        cfg = db_handler.get_verification_config(self.bot.CONN, guild.id)
        role = guild.get_role(cfg['role_id']) if cfg else None
        if role is None:
            await interaction.response.edit_message(
                content="The verified role no longer exists. Please alert a server admin.",
                view=None,
            )
            return

        try:
            await member.add_roles(role, reason="Passed verification captcha")
        except discord.Forbidden:
            await interaction.response.edit_message(
                content="I could not assign the verified role — my role is likely below it. "
                        "Please alert a server admin.",
                view=None,
            )
            return
        except discord.HTTPException:
            await interaction.response.edit_message(
                content="Something went wrong assigning your role. Please try again shortly.",
                view=None,
            )
            return

        self._attempts.pop(key, None)
        await interaction.response.edit_message(
            content=f"Verification successful — you have been granted **{role.name}**. Welcome!",
            view=None,
        )

        await logger.log_action(
            self.bot, guild, "Member Verified", member,
            details={
                "Member":       f"{member.mention} — `{member}` (`{member.id}`)",
                "Role Granted": role.mention,
                "Solved In":    f"{elapsed:.1f}s",
                "Account Age":  f"<t:{int(member.created_at.timestamp())}:R>",
                "Joined":       (f"<t:{int(member.joined_at.timestamp())}:R>"
                                 if getattr(member, "joined_at", None) else "unknown"),
            },
            level='success',
            channel=self._join_log_channel(guild, cfg),
        )

    # /verify-setup

    async def _post_panel(self, channel, guild) -> discord.Message:
        branding = db_handler.get_guild_branding(self.bot.CONN, guild.id)
        embed = discord.Embed(
            title=f"Welcome to {guild.name}",
            description=(
                "Press **Verify** below to gain access to the server.\n\n"
                "You will be asked to solve a short maths captcha. "
                "Only you can see it, and it takes a few seconds."
            ),
            color=branding['color'],
        )
        if branding['footer']:
            embed.set_footer(text=branding['footer'], icon_url=branding['icon_url'] or None)
        if guild.icon:
            embed.set_thumbnail(url=guild.icon.url)
        return await channel.send(embed=embed, view=VerifyPanelView(self))

    @commands.guild_only()
    @commands.cooldown(1, 10, commands.BucketType.guild)
    @commands.slash_command(
        name="verify-setup",
        description="[Owner] Set up captcha verification and post the panel. Requires 2FA."
    )
    async def verify_setup(
        self, ctx: discord.ApplicationContext,
        channel: Option(discord.TextChannel, "Channel to post the verify panel in", required=True),
        role: Option(discord.Role, "Role granted on success", required=True),
        code: Option(int, "Your 6-digit 2FA code", required=True),
        min_account_age: Option(
            int, "Minimum Discord account age in hours (0 to disable)",
            required=False, default=0, min_value=0, max_value=8760),
        join_log_channel: Option(
            discord.TextChannel,
            "Optional: send join/verification logs here instead of the main log channel",
            required=False, default=None),
    ):
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

        # The bot must outrank the role to be able to grant it - check now
        # rather than letting every member discover it at the last step.
        me = ctx.guild.me
        if me is None or role >= me.top_role:
            await ctx.respond(
                f"**{role.name}** is above my highest role, so I cannot grant it. "
                "Move my role above it in Server Settings → Roles, then run this again.",
                ephemeral=True)
            return

        if role.permissions.administrator or role.permissions.manage_guild:
            await ctx.respond(
                f"**{role.name}** carries administrator or manage-server permissions. "
                "Refusing to hand that to anyone who solves a captcha — pick a plain member role.",
                ephemeral=True)
            return

        try:
            panel = await self._post_panel(channel, ctx.guild)
        except discord.Forbidden:
            await ctx.respond(
                f"I cannot post in {channel.mention}. Grant me Send Messages and Embed Links there.",
                ephemeral=True)
            return

        db_handler.set_verification_config(
            self.bot.CONN, ctx.guild.id, channel.id, role.id, min_account_age,
            log_channel_id=join_log_channel.id if join_log_channel else None)
        db_handler.set_verification_panel(self.bot.CONN, ctx.guild.id, panel.id)

        cfg = db_handler.get_verification_config(self.bot.CONN, ctx.guild.id)
        age_note = (f"{min_account_age} hour(s)" if min_account_age else "not enforced")
        existing_log = self.bot.get_channel(cfg['log_channel_id']) if cfg['log_channel_id'] else None
        log_note = existing_log.mention if existing_log else "main log channel (default)"

        await ctx.respond(
            f"Verification is live in {channel.mention}.\n"
            f"Role granted: {role.mention}\n"
            f"Minimum account age: **{age_note}**\n"
            f"Join logs go to: {log_note}\n\n"
            "Change the join log destination any time with `/verify-log-channel`.",
            ephemeral=True)

        await logger.log_action(
            self.bot, ctx.guild, "Verification Configured", ctx.author,
            details={
                "Channel": channel.mention,
                "Role": role.mention,
                "Min Account Age": age_note,
                "Join Logs": log_note,
            },
            level='success')

    # /verify-log-channel

    @commands.guild_only()
    @commands.slash_command(
        name="verify-log-channel",
        description="[Owner] Send join/verification logs to their own channel. Requires 2FA."
    )
    async def verify_log_channel(
        self, ctx: discord.ApplicationContext,
        code: Option(int, "Your 6-digit 2FA code", required=True),
        channel: Option(
            discord.TextChannel,
            "Channel for join logs. Leave empty to go back to the main log channel.",
            required=False, default=None),
    ):
        allowed, err = permissions.check(self.bot, ctx, 'owner')
        if not allowed:
            await ctx.respond(err, ephemeral=True)
            return

        if not two_factor_helper.verify_code(self.bot.CONN, ctx.author.id, code):
            await ctx.respond("Incorrect 2FA code.", ephemeral=True)
            return

        cfg = db_handler.get_verification_config(self.bot.CONN, ctx.guild.id)
        if not cfg:
            await ctx.respond("Verification is not set up yet — run `/verify-setup`.", ephemeral=True)
            return

        if channel is not None:
            perms = channel.permissions_for(ctx.guild.me)
            if not (perms.send_messages and perms.embed_links):
                await ctx.respond(
                    f"I need **Send Messages** and **Embed Links** in {channel.mention}.",
                    ephemeral=True)
                return

        db_handler.set_verification_log_channel(
            self.bot.CONN, ctx.guild.id, channel.id if channel else None)

        target = channel.mention if channel else "the main log channel"
        await ctx.respond(f"Join and verification logs will now go to {target}.", ephemeral=True)
        await logger.log_action(
            self.bot, ctx.guild, "Verification Log Channel Changed", ctx.author,
            details={"Destination": target},
            level='info')

    # /verify-panel

    @commands.guild_only()
    @commands.cooldown(1, 10, commands.BucketType.guild)
    @commands.slash_command(
        name="verify-panel",
        description="[Owner] Re-post the verification panel using the saved settings. Requires 2FA."
    )
    async def verify_panel(self, ctx: discord.ApplicationContext,
                           code: Option(int, "Your 6-digit 2FA code", required=True)):
        allowed, err = permissions.check(self.bot, ctx, 'owner')
        if not allowed:
            await ctx.respond(err, ephemeral=True)
            return

        if not two_factor_helper.verify_code(self.bot.CONN, ctx.author.id, code):
            await ctx.respond("Incorrect 2FA code.", ephemeral=True)
            return

        cfg = db_handler.get_verification_config(self.bot.CONN, ctx.guild.id)
        if not cfg:
            await ctx.respond("Verification is not set up yet — run `/verify-setup`.", ephemeral=True)
            return

        channel = self.bot.get_channel(cfg['channel_id'])
        if channel is None:
            await ctx.respond("The configured channel no longer exists. Run `/verify-setup` again.",
                              ephemeral=True)
            return

        try:
            panel = await self._post_panel(channel, ctx.guild)
        except discord.Forbidden:
            await ctx.respond(f"I cannot post in {channel.mention}.", ephemeral=True)
            return

        db_handler.set_verification_panel(self.bot.CONN, ctx.guild.id, panel.id)
        await ctx.respond(f"Panel re-posted in {channel.mention}.", ephemeral=True)

    # /verify-toggle

    @commands.guild_only()
    @commands.slash_command(
        name="verify-toggle",
        description="[Owner] Enable or disable verification without losing the setup. Requires 2FA."
    )
    async def verify_toggle(self, ctx: discord.ApplicationContext,
                            code: Option(int, "Your 6-digit 2FA code", required=True)):
        allowed, err = permissions.check(self.bot, ctx, 'owner')
        if not allowed:
            await ctx.respond(err, ephemeral=True)
            return

        if not two_factor_helper.verify_code(self.bot.CONN, ctx.author.id, code):
            await ctx.respond("Incorrect 2FA code.", ephemeral=True)
            return

        cfg = db_handler.get_verification_config(self.bot.CONN, ctx.guild.id)
        if not cfg:
            await ctx.respond("Verification is not set up yet — run `/verify-setup`.", ephemeral=True)
            return

        new_state = not bool(cfg['enabled'])
        db_handler.set_verification_enabled(self.bot.CONN, ctx.guild.id, new_state)
        label = "ENABLED" if new_state else "DISABLED"
        await ctx.respond(f"Verification is now **{label}**.", ephemeral=True)
        await logger.log_action(
            self.bot, ctx.guild, f"Verification {label}", ctx.author,
            level='success' if new_state else 'warning')

    # /verify-status  (view-only - any keycard)

    @commands.guild_only()
    @commands.slash_command(
        name="verify-status",
        description="View the current verification configuration."
    )
    async def verify_status(self, ctx: discord.ApplicationContext):
        allowed, err = permissions.check(self.bot, ctx, 'any_registered')
        if not allowed:
            await ctx.respond(err, ephemeral=True)
            return

        cfg = db_handler.get_verification_config(self.bot.CONN, ctx.guild.id)
        if not cfg:
            await ctx.respond("Verification is not set up in this server.", ephemeral=True)
            return

        channel = self.bot.get_channel(cfg['channel_id'])
        role = ctx.guild.get_role(cfg['role_id'])
        self._prune_sessions()

        embed = discord.Embed(
            title="Verification Status",
            color=self._brand_color(ctx.guild.id),
        )
        embed.add_field(name="State", value="Enabled" if cfg['enabled'] else "Disabled", inline=True)
        embed.add_field(name="Channel", value=channel.mention if channel else "missing", inline=True)
        embed.add_field(name="Role", value=role.mention if role else "missing", inline=True)
        embed.add_field(
            name="Min Account Age",
            value=f"{cfg['min_account_age']}h" if cfg['min_account_age'] else "Not enforced",
            inline=True)
        join_log = self._join_log_channel(ctx.guild, cfg)
        embed.add_field(
            name="Join Logs",
            value=join_log.mention if join_log else "Main log channel",
            inline=True)
        embed.add_field(name="Challenges In Flight", value=str(len(self._sessions)), inline=True)
        await ctx.respond(embed=embed, ephemeral=True)


def setup(bot):
    bot.add_cog(Verification(bot))
