"""
Name Filter — block users whose username or nickname matches configured patterns.

Commands (all under /name-filter):
  /name-filter add phrase <pattern>      Add a single phrase (substring) filter
  /name-filter add regex <pattern>       Add a single regex pattern filter
  /name-filter import phrase             Paste 50+ phrase filters at once via modal
  /name-filter import regex              Paste 50+ regex filters at once via modal
  /name-filter remove <id>               Remove a filter by its ID
  /name-filter list [page]               Browse all active filters, 10 per page
  /name-filter test <name>               Check if a name would be caught
  /name-filter set-action <action>       Configure what happens on a match (ban/kick/timeout)
  /name-filter cleanse                   Retroactively scan all current members

Triggers:
  - on_member_join       — username and display name checked immediately on join
  - on_member_update     — nickname changes checked in real time
  - on_user_update       — global username changes checked across all shared guilds

Exempt from filtering:
  - Bots
  - Bot master user (MASTER_USER_ID)
  - Trusted members (announcers) registered in the guild

Default action: ban. Configurable per guild via /name-filter set-action.
"""

import asyncio
import re
import time
from datetime import timedelta

import discord
from discord.ext import commands, tasks
from discord.commands import Option

import db_handler
import logger
import permissions
import two_factor_helper


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

MAX_PATTERN_LENGTH = 200

# /name-filter cleanse refuses to run when it would hit more than this share of
# eligible members (and more than this many people), on the assumption that a
# filter matching most of the server is a mistake rather than an attack.
CLEANSE_ABORT_SHARE = 0.25
CLEANSE_ABORT_MIN = 10

# ---------------------------------------------------------------------------
# Burst (raid) log aggregation
#
# Discord allows roughly 5 messages per 5 seconds in a channel. A 500-account
# raid producing one embed per match is ~8 minutes of backlog: the log channel
# becomes the bottleneck, every other log queues behind it, and the bot looks
# frozen precisely when someone is watching it.
#
# So: below the threshold, log each match individually (the normal, useful
# case). Once matches arrive faster than that, switch to collecting them and
# emitting one periodic summary until the burst ends.
# ---------------------------------------------------------------------------

BURST_THRESHOLD = 8       # matches within the window before aggregating
BURST_WINDOW = 20.0       # seconds
BURST_FLUSH_INTERVAL = 15.0
BURST_SUMMARY_SAMPLE = 15  # names shown per summary embed
BURST_MAX_TRACKED = 500    # cap on the rolling timestamp window
BURST_MAX_BUFFERED = 1000  # cap on names held for the next summary


class _BurstTracker:
    """Per-guild rolling counter that decides individual vs aggregated logging."""

    def __init__(self):
        self.recent: list[float] = []
        self.buffer: list[tuple[str, str, str]] = []  # (name, pattern, action)
        self.last_flush = 0.0
        self.active = False

    def record(self) -> bool:
        """Register a match; return True if we are in burst mode."""
        now = time.monotonic()
        self.recent = [t for t in self.recent if now - t < BURST_WINDOW]
        self.recent.append(now)
        # Age-based pruning alone is not enough: a heavy raid can land tens of
        # thousands of matches inside one window, and we only ever need to know
        # that the threshold was crossed. Keep the list bounded.
        if len(self.recent) > BURST_MAX_TRACKED:
            del self.recent[:-BURST_MAX_TRACKED]
        if len(self.buffer) > BURST_MAX_BUFFERED:
            # Keep the earliest entries — they identify the start of the attack.
            del self.buffer[BURST_MAX_BUFFERED:]
        if len(self.recent) >= BURST_THRESHOLD:
            if not self.active:
                self.active = True
                self.last_flush = now
        elif self.active and not self.recent:
            self.active = False
        return self.active

    def should_flush(self) -> bool:
        return bool(self.buffer) and (time.monotonic() - self.last_flush) >= BURST_FLUSH_INTERVAL

    def drain(self) -> list[tuple[str, str, str]]:
        items, self.buffer = self.buffer, []
        self.last_flush = time.monotonic()
        return items


_bursts: dict[int, _BurstTracker] = {}


def _burst(guild_id: int) -> _BurstTracker:
    return _bursts.setdefault(guild_id, _BurstTracker())


async def _flush_burst(bot, guild: discord.Guild, force: bool = False):
    """Emit one summary embed for everything collected during a burst."""
    tracker = _burst(guild.id)
    if not tracker.buffer:
        return
    if not force and not tracker.should_flush():
        return

    items = tracker.drain()
    sample = items[:BURST_SUMMARY_SAMPLE]
    lines = "\n".join(f"• `{n}` — matched `{p}` → {a}" for n, p, a in sample)
    if len(items) > len(sample):
        lines += f"\n… and {len(items) - len(sample)} more"

    await logger.log_action(
        bot, guild,
        "Name Filter — Burst Summary",
        guild.me,
        details={
            "Matches In This Batch": str(len(items)),
            "Detail": lines,
            "Note": (
                "Matches are arriving faster than the log channel can carry them, "
                "so entries are batched. This usually means a raid. Consider "
                "`/panic` if it continues, and check the server's join settings."
            ),
        },
        level='critical',
    )

# Constructs that make catastrophic backtracking possible.
#
#   1. A quantified group containing a quantifier:  (a+)+  (a*)*  (ab+)*
#   2. A quantified group containing an alternation: (a|a)+  (a|ab)+
#
# The second form is just as explosive as the first — the engine has to try
# every combination of branches — but the original rule only looked for nested
# quantifiers, so (a|a)+ sailed through. Quantified alternations are rare in
# legitimate name filters, so rejecting the whole shape is the right trade.
_NESTED_QUANTIFIER = re.compile(r"\([^)]*[+*}][^)]*\)\s*[+*{]")
_QUANTIFIED_ALTERNATION = re.compile(r"\((?![?]:?[=!<])[^)]*\|[^)]*\)\s*[+*{]")

# Names are short; anything longer is truncated before matching so a pathological
# pattern has little input to chew on even if one slips through.
_MAX_NAME_LENGTH = 128


def validate_regex(pattern: str) -> tuple[bool, str]:
    """
    Check a user-supplied regex is safe to run on the event loop.

    re.compile() only catches syntax errors. It happily accepts patterns like
    (a+)+$ whose backtracking is exponential in the input length — running one
    of those on every join / nickname change would freeze the entire bot, not
    just the name filter. Reject the dangerous shapes up front.
    """
    if not pattern or not pattern.strip():
        return False, "Pattern is empty."
    if len(pattern) > MAX_PATTERN_LENGTH:
        return False, f"Pattern is too long (max {MAX_PATTERN_LENGTH} characters)."
    try:
        re.compile(pattern)
    except re.error as exc:
        return False, f"Invalid regex syntax: {exc}"
    if _NESTED_QUANTIFIER.search(pattern):
        return False, (
            "Pattern contains a nested quantifier such as `(a+)+` or `(x*)*`. "
            "These can hang the bot on certain names (catastrophic backtracking). "
            "Rewrite it without a quantifier inside a quantified group."
        )
    if _QUANTIFIED_ALTERNATION.search(pattern):
        return False, (
            "Pattern contains a repeated alternation such as `(a|b)+`. "
            "These can hang the bot on certain names (catastrophic backtracking). "
            "Use a character class like `[ab]+`, or drop the repetition."
        )
    return True, ""


def _match(filters: list, name: str):
    """
    Check `name` against every filter in the list.
    Returns (matched_filter_dict, name) on first match, or (None, None).
    Silently skips filters with broken regex rather than crashing.
    """
    if not name:
        return None, None
    # Bound the work a single pattern can do, regardless of what got stored.
    probe = name[:_MAX_NAME_LENGTH]
    lowered = probe.lower()
    for f in filters:
        try:
            if f['type'] == 'phrase':
                if f['pattern'].lower() in lowered:
                    return f, name
            else:
                if re.search(f['pattern'], probe):
                    return f, name
        except re.error:
            pass
    return None, None


def _is_exempt(bot, guild: discord.Guild, member_id: int) -> bool:
    """
    Return True if this member should be skipped by the name filter.

    Exempt: bot master, server owner, server staff (anyone who can kick, ban,
    moderate, or administer), announcers, and link managers.

    Staff are exempt because an over-broad pattern would otherwise ban the very
    people who need to fix it — a `/name-filter cleanse` with a loose regex
    could remove every moderator before anyone could intervene.
    """
    if member_id == bot.master_user:
        return True
    if member_id == guild.owner_id:
        return True

    member = guild.get_member(member_id)
    if member is not None:
        perms = member.guild_permissions
        if (perms.administrator or perms.ban_members or perms.kick_members
                or perms.manage_guild or perms.moderate_members):
            return True

    if db_handler.check_authorised(bot.CONN, (guild.id, member_id)):
        return True
    return db_handler.is_link_manager(bot.CONN, guild.id, member_id)


def _action_label(action: str) -> str:
    """Human-readable name for a stored action value."""
    if action.startswith('timeout:'):
        return f"Timeout ({action.split(':', 1)[1]}h)"
    if action == 'flag':
        return "Flag (log only — no automatic action)"
    return action.title()


def _account_age_str(member: discord.Member) -> str:
    """Human-readable account age string."""
    now = discord.utils.utcnow()
    delta = now - member.created_at
    days = delta.days
    if days < 1:
        hours = delta.seconds // 3600
        return f"{hours} hour(s) old — **very new account**"
    if days < 7:
        return f"{days} day(s) old — **recently created**"
    if days < 30:
        return f"{days} days old"
    months = days // 30
    rem = days % 30
    return f"{months} month(s), {rem} day(s) old"


async def _take_action(
    bot,
    guild: discord.Guild,
    member: discord.Member,
    action: str,
    matched_filter: dict,
    matched_name: str,
    trigger: str,
):
    """
    Apply the configured action to the member and send a richly detailed
    log entry explaining exactly what happened and why.
    """
    filter_type_label = "Phrase (exact substring)" if matched_filter['type'] == 'phrase' else "Regex (pattern match)"

    # Build the audit-log reason string (appears in Discord's audit log)
    audit_reason = (
        f"[Name Filter] {trigger} — "
        f"[{matched_filter['type'].upper()}] `{matched_filter['pattern']}` "
        f"matched name: {matched_name!r}"
    )

    log_title = "Name Filter Triggered"
    action_taken_label = "Unknown"
    action_level = 'critical'

    try:
        if action == 'flag':
            # Report only. A pattern match is evidence, not proof — a human
            # decides. Mirrors the link filter, where the bot removes the
            # content and a moderator judges the person.
            action_taken_label = "None — flagged for moderator review"
            action_level = 'warning'
            log_title = "Name Filter — Flagged for Review"
        elif action == 'kick':
            await member.kick(reason=audit_reason)
            action_taken_label = "Kicked from server"
            action_level = 'warning'
            log_title = "Name Filter — Member Kicked"
        elif action.startswith('timeout:'):
            hours = int(action.split(':', 1)[1])
            until = discord.utils.utcnow() + timedelta(hours=hours)
            await member.timeout(until, reason=audit_reason)
            action_taken_label = f"Timed out for {hours} hour(s)"
            action_level = 'warning'
            log_title = "Name Filter — Member Timed Out"
        else:
            # Explicit ban
            await member.ban(reason=audit_reason, delete_message_days=0)
            action_taken_label = "Permanently banned from server"
            log_title = "Name Filter — Member Banned"
    except discord.Forbidden:
        action_taken_label = "Action FAILED — bot lacks permission (check role hierarchy)"
        action_level = 'error'
        log_title = "Name Filter — Action Failed"
    except discord.HTTPException as exc:
        action_taken_label = f"Action FAILED — {exc}"
        action_level = 'error'
        log_title = "Name Filter — Action Failed"

    # -----------------------------------------------------------------------
    # Send a descriptive log embed so moderators understand exactly what
    # happened, which rule matched, and what (if anything) they need to do.
    # -----------------------------------------------------------------------
    if action == 'flag':
        why = (
            f"**No action was taken — this is a report.**\n"
            f"{member.mention} matched a name pattern your team configured to catch "
            f"impersonators and fake support accounts. Review the account and decide: "
            f"ban if it is a scammer, or remove the pattern with "
            f"`/name-filter remove` if this was a false positive."
        )
    else:
        why = (
            "This member's name matched a pattern your moderation team "
            "configured to block impersonators, fake support/staff accounts, "
            "scam bots, or other deceptive usernames. The filter triggered "
            f"automatically because `{matched_name}` satisfied the rule."
        )

    # During a raid, collapse per-match embeds into periodic summaries so the
    # log channel does not become the bottleneck (see _BurstTracker).
    tracker = _burst(guild.id)
    if tracker.record():
        tracker.buffer.append((matched_name, matched_filter['pattern'], action_taken_label))
        await _flush_burst(bot, guild)
        return

    await logger.log_action(
        bot,
        guild,
        log_title,
        member,
        details={
            "Member":          f"{member.mention} — `{member}` (`{member.id}`)",
            "Matched Name":    f"`{matched_name}`",
            "Name Type":       trigger,
            "Blocked Pattern": f"`{matched_filter['pattern']}`  (ID: {matched_filter['id']})",
            "Filter Type":     filter_type_label,
            "Action Taken":    action_taken_label,
            "Account Age":     _account_age_str(member),
            "Why":             why,
        },
        level=action_level,
    )


# ---------------------------------------------------------------------------
# Bulk import modal
# ---------------------------------------------------------------------------

class BulkImportModal(discord.ui.Modal):
    def __init__(self, bot, guild_id: int, guild: discord.Guild, actor, filter_type: str):
        super().__init__(title=f"Import {filter_type.title()} Filters")
        self.bot         = bot
        self.guild_id    = guild_id
        self.guild       = guild
        self.actor       = actor
        self.filter_type = filter_type

        if filter_type == 'phrase':
            hint = "support\nmetamask\nofficial\nadmin\ncustomer service\nverification"
        else:
            hint = "(?i)metamask\n(?i)^admin\n(?i) support$\n(?i)official\n(?i)^mod"

        self.add_item(discord.ui.InputText(
            label=f"{filter_type.title()} filters — one per line",
            style=discord.InputTextStyle.paragraph,
            placeholder=hint,
            required=True,
            max_length=4000,
        ))

    async def callback(self, interaction: discord.Interaction):
        raw      = self.children[0].value
        patterns = [line.strip() for line in raw.splitlines() if line.strip()]

        if not patterns:
            await interaction.response.send_message("No patterns found in input.", ephemeral=True)
            return

        added           = 0
        skipped_dup     = 0
        skipped_invalid = 0
        bad_patterns    = []

        for pattern in patterns:
            # Validate regex before inserting — rejects unsafe patterns as well
            # as syntactically invalid ones.
            if self.filter_type == 'regex':
                ok_pattern, why = validate_regex(pattern)
                if not ok_pattern:
                    skipped_invalid += 1
                    bad_patterns.append(f"`{pattern[:50]}` — {why}")
                    continue

            ok = db_handler.insert_name_filter(
                self.bot.CONN, self.guild_id, self.filter_type, pattern, interaction.user.id
            )
            if ok:
                added += 1
            else:
                skipped_dup += 1

        # Build feedback message
        lines = [f"**{added}** {self.filter_type} filter(s) added successfully."]
        if skipped_dup:
            lines.append(f"**{skipped_dup}** skipped — already exist in this server.")
        if skipped_invalid:
            lines.append(f"**{skipped_invalid}** skipped — invalid regex syntax:")
            for bp in bad_patterns[:5]:
                lines.append(f"  • {bp}")
            if len(bad_patterns) > 5:
                lines.append(f"  … and {len(bad_patterns) - 5} more.")

        await interaction.response.send_message("\n".join(lines), ephemeral=True)

        if added > 0:
            await logger.log_action(
                self.bot, self.guild,
                "Name Filters Bulk Imported",
                self.actor,
                details={
                    "Filter Type": self.filter_type.title(),
                    "Added":       str(added),
                    "Duplicates":  str(skipped_dup),
                    "Invalid":     str(skipped_invalid),
                },
                level='info',
            )


# ---------------------------------------------------------------------------
# Cog
# ---------------------------------------------------------------------------

class NameFilter(commands.Cog):
    def __init__(self, bot):
        self.bot = bot
        self.flush_bursts.start()

    def cog_unload(self):
        self.flush_bursts.cancel()

    # ------------------------------------------------------------------
    # Background task: emit pending burst summaries
    # ------------------------------------------------------------------

    @tasks.loop(seconds=BURST_FLUSH_INTERVAL)
    async def flush_bursts(self):
        """
        Flush buffered matches even after a raid stops.

        Aggregation is triggered by incoming matches, so without this the final
        few entries of a burst would sit in the buffer indefinitely once the
        joins dried up — the tail of an attack is exactly the part you want in
        the log.
        """
        for guild_id, tracker in list(_bursts.items()):
            guild = self.bot.get_guild(guild_id)
            if guild is None:
                _bursts.pop(guild_id, None)
                continue
            if tracker.buffer:
                try:
                    await _flush_burst(self.bot, guild, force=True)
                except Exception as e:
                    print(f"[name_filter] Burst flush failed for {guild_id}: {e}")
            # Burst is over once the rolling window has emptied.
            if tracker.active and not tracker.recent and not tracker.buffer:
                tracker.active = False

    @flush_bursts.before_loop
    async def before_flush(self):
        await self.bot.wait_until_ready()

    nf        = discord.SlashCommandGroup("name-filter",  "Manage name-based security filters")
    nf_add    = nf.create_subgroup("add",    "Add a single filter")
    nf_import = nf.create_subgroup("import", "Bulk import filters via modal")

    # ------------------------------------------------------------------
    # /name-filter add phrase
    # ------------------------------------------------------------------

    @nf_add.command(
        name="phrase",
        description="Add a single phrase filter. Blocks any name containing this text (case-insensitive).",
    )
    @commands.cooldown(1, 3, commands.BucketType.user)
    async def add_phrase(
        self,
        ctx: discord.ApplicationContext,
        pattern: Option(str, "Keyword or phrase to block", required=True),
        code: Option(int, "Your 6-digit 2FA code", required=True),
    ):
        allowed, err = permissions.check(self.bot, ctx, 'announcer')
        if not allowed:
            await ctx.respond(err, ephemeral=True)
            return
        ok2, err2 = permissions.guild_required(self.bot, ctx)
        if not ok2:
            await ctx.respond(err2, ephemeral=True)
            return

        if not two_factor_helper.verify_code(self.bot.CONN, ctx.author.id, code):
            await ctx.respond("Incorrect 2FA code.", ephemeral=True)
            return

        ok = db_handler.insert_name_filter(self.bot.CONN, ctx.guild.id, 'phrase', pattern, ctx.author.id)
        if not ok:
            await ctx.respond(f"Phrase filter `{pattern}` already exists.", ephemeral=True)
            return
        await ctx.respond(f"Phrase filter added: `{pattern}`", ephemeral=True)
        await logger.log_action(
            self.bot, ctx.guild, "Name Filter Added", ctx.author,
            details={"Type": "Phrase", "Pattern": f"`{pattern}`"},
            level='info',
        )

    # ------------------------------------------------------------------
    # /name-filter add regex
    # ------------------------------------------------------------------

    @nf_add.command(
        name="regex",
        description="Add a regex pattern filter. Use (?i) prefix for case-insensitive matching.",
    )
    @commands.cooldown(1, 3, commands.BucketType.user)
    async def add_regex(
        self,
        ctx: discord.ApplicationContext,
        pattern: Option(str, "Regex pattern (Python re syntax)", required=True),
        code: Option(int, "Your 6-digit 2FA code", required=True),
    ):
        allowed, err = permissions.check(self.bot, ctx, 'announcer')
        if not allowed:
            await ctx.respond(err, ephemeral=True)
            return
        ok2, err2 = permissions.guild_required(self.bot, ctx)
        if not ok2:
            await ctx.respond(err2, ephemeral=True)
            return

        if not two_factor_helper.verify_code(self.bot.CONN, ctx.author.id, code):
            await ctx.respond("Incorrect 2FA code.", ephemeral=True)
            return

        ok_pattern, why = validate_regex(pattern)
        if not ok_pattern:
            await ctx.respond(why, ephemeral=True)
            return

        ok = db_handler.insert_name_filter(self.bot.CONN, ctx.guild.id, 'regex', pattern, ctx.author.id)
        if not ok:
            await ctx.respond(f"Regex filter `{pattern}` already exists.", ephemeral=True)
            return
        await ctx.respond(f"Regex filter added: `{pattern}`", ephemeral=True)
        await logger.log_action(
            self.bot, ctx.guild, "Name Filter Added", ctx.author,
            details={"Type": "Regex", "Pattern": f"`{pattern}`"},
            level='info',
        )

    # ------------------------------------------------------------------
    # /name-filter import phrase
    # ------------------------------------------------------------------

    @nf_import.command(
        name="phrase",
        description="Open a modal and paste up to 100+ phrase filters at once — one per line. Requires 2FA.",
    )
    async def import_phrase(
        self,
        ctx: discord.ApplicationContext,
        code: Option(int, "Your 6-digit 2FA code", required=True),
    ):
        allowed, err = permissions.check(self.bot, ctx, 'announcer')
        if not allowed:
            await ctx.respond(err, ephemeral=True)
            return
        ok2, err2 = permissions.guild_required(self.bot, ctx)
        if not ok2:
            await ctx.respond(err2, ephemeral=True)
            return
        if not two_factor_helper.verify_code(self.bot.CONN, ctx.author.id, code):
            await ctx.respond("Incorrect 2FA code.", ephemeral=True)
            return
        await ctx.send_modal(
            BulkImportModal(self.bot, ctx.guild.id, ctx.guild, ctx.author, 'phrase')
        )

    # ------------------------------------------------------------------
    # /name-filter import regex
    # ------------------------------------------------------------------

    @nf_import.command(
        name="regex",
        description="Open a modal and paste up to 100+ regex filters at once — one per line. Requires 2FA.",
    )
    async def import_regex(
        self,
        ctx: discord.ApplicationContext,
        code: Option(int, "Your 6-digit 2FA code", required=True),
    ):
        allowed, err = permissions.check(self.bot, ctx, 'announcer')
        if not allowed:
            await ctx.respond(err, ephemeral=True)
            return
        ok2, err2 = permissions.guild_required(self.bot, ctx)
        if not ok2:
            await ctx.respond(err2, ephemeral=True)
            return
        if not two_factor_helper.verify_code(self.bot.CONN, ctx.author.id, code):
            await ctx.respond("Incorrect 2FA code.", ephemeral=True)
            return
        await ctx.send_modal(
            BulkImportModal(self.bot, ctx.guild.id, ctx.guild, ctx.author, 'regex')
        )

    # ------------------------------------------------------------------
    # /name-filter remove
    # ------------------------------------------------------------------

    @nf.command(
        name="remove",
        description="Remove a filter by its ID. Find IDs with /name-filter list. Requires 2FA.",
    )
    @commands.cooldown(1, 3, commands.BucketType.user)
    async def remove_filter(
        self,
        ctx: discord.ApplicationContext,
        filter_id: Option(int, "Filter ID shown in /name-filter list", required=True),
        code: Option(int, "Your 6-digit 2FA code", required=True),
    ):
        allowed, err = permissions.check(self.bot, ctx, 'announcer')
        if not allowed:
            await ctx.respond(err, ephemeral=True)
            return
        ok2, err2 = permissions.guild_required(self.bot, ctx)
        if not ok2:
            await ctx.respond(err2, ephemeral=True)
            return

        if not two_factor_helper.verify_code(self.bot.CONN, ctx.author.id, code):
            await ctx.respond("Incorrect 2FA code.", ephemeral=True)
            return

        # Fetch before deleting so we can log the pattern
        filters = db_handler.get_name_filters(self.bot.CONN, ctx.guild.id)
        target  = next((f for f in filters if f['id'] == filter_id), None)

        removed = db_handler.delete_name_filter(self.bot.CONN, ctx.guild.id, filter_id)
        if not removed:
            await ctx.respond(
                f"No filter with ID `{filter_id}` found in this server. "
                "Use `/name-filter list` to see valid IDs.",
                ephemeral=True,
            )
            return

        pattern_info = f"`{target['pattern']}`" if target else f"ID {filter_id}"
        await ctx.respond(f"Filter removed: {pattern_info}", ephemeral=True)
        await logger.log_action(
            self.bot, ctx.guild, "Name Filter Removed", ctx.author,
            details={
                "Filter ID": str(filter_id),
                "Pattern":   f"`{target['pattern']}`" if target else "—",
                "Type":      target['type'].title() if target else "—",
            },
            level='warning',
        )

    # ------------------------------------------------------------------
    # /name-filter list
    # ------------------------------------------------------------------

    @nf.command(
        name="list",
        description="Post all active name filters to the log channel (regex first, then phrase).",
    )
    async def list_filters(
        self,
        ctx: discord.ApplicationContext,
    ):
        allowed, err = permissions.check(self.bot, ctx, 'announcer')
        if not allowed:
            await ctx.respond(err, ephemeral=True)
            return
        ok2, err2 = permissions.guild_required(self.bot, ctx)
        if not ok2:
            await ctx.respond(err2, ephemeral=True)
            return

        filters = db_handler.get_name_filters(self.bot.CONN, ctx.guild.id)
        if not filters:
            await ctx.respond(
                "No name filters configured yet.\n"
                "Use `/name-filter add phrase` or `/name-filter import phrase` to get started.",
                ephemeral=True,
            )
            return

        log_ch = logger.get_log_channel(self.bot, ctx.guild)
        if not log_ch:
            await ctx.respond("No log channel configured. Run `/set-logs` first.", ephemeral=True)
            return

        action       = db_handler.get_name_filter_action(self.bot.CONN, ctx.guild.id)
        action_label = _action_label(action)

        regex_filters  = [f for f in filters if f['type'] == 'regex']
        phrase_filters = [f for f in filters if f['type'] == 'phrase']

        async def send_block(header: str, items: list):
            """Send items as one or more copyable code blocks, splitting at 1800 chars."""
            lines = [f['pattern'] for f in items]
            chunks = []
            current = ""
            for line in lines:
                if len(current) + len(line) + 1 > 1800:
                    chunks.append(current)
                    current = line
                else:
                    current = f"{current}\n{line}" if current else line
            if current:
                chunks.append(current)

            first = True
            for chunk in chunks:
                title_part = header if first else f"{header} (cont.)"
                await log_ch.send(f"**{title_part}**\n```\n{chunk}\n```")
                first = False

        # Summary header embed
        summary = discord.Embed(
            title=f"Name Filter List — {ctx.guild.name}",
            description=(
                f"**{len(filters)}** filter(s) active • "
                f"**{len(regex_filters)}** regex • "
                f"**{len(phrase_filters)}** phrase\n"
                f"Action on match: **{action_label}**\n"
                f"Requested by {ctx.author.mention}"
            ),
            color=0x5865F2,
            timestamp=discord.utils.utcnow(),
        )
        await log_ch.send(embed=summary)

        if regex_filters:
            await send_block(f"REGEX FILTERS ({len(regex_filters)})", regex_filters)
        if phrase_filters:
            await send_block(f"PHRASE FILTERS ({len(phrase_filters)})", phrase_filters)

        await ctx.respond(
            f"Filter list posted to {log_ch.mention} — "
            f"**{len(regex_filters)}** regex, **{len(phrase_filters)}** phrase.",
            ephemeral=True,
        )

    # ------------------------------------------------------------------
    # /name-filter test
    # ------------------------------------------------------------------

    @nf.command(
        name="test",
        description="Check whether a specific name would be caught by any active filter.",
    )
    async def test_filter(
        self,
        ctx: discord.ApplicationContext,
        name: Option(str, "The username or nickname to test", required=True),
    ):
        allowed, err = permissions.check(self.bot, ctx, 'announcer')
        if not allowed:
            await ctx.respond(err, ephemeral=True)
            return
        ok2, err2 = permissions.guild_required(self.bot, ctx)
        if not ok2:
            await ctx.respond(err2, ephemeral=True)
            return

        filters = db_handler.get_name_filters(self.bot.CONN, ctx.guild.id)
        if not filters:
            await ctx.respond("No filters configured — nothing to test against.", ephemeral=True)
            return

        matched_filter, _ = _match(filters, name)
        if matched_filter:
            ftype = "Phrase" if matched_filter['type'] == 'phrase' else "Regex"
            await ctx.respond(
                f"**Match found** for `{name}`\n"
                f"Filter `#{matched_filter['id']}` [{ftype}]: `{matched_filter['pattern']}`\n"
                f"This name **would be actioned** if a real member used it.",
                ephemeral=True,
            )
        else:
            await ctx.respond(
                f"**No match** — `{name}` passes all {len(filters)} active filter(s).",
                ephemeral=True,
            )

    # ------------------------------------------------------------------
    # /name-filter set-action
    # ------------------------------------------------------------------

    @nf.command(
        name="set-action",
        description="[Owner] Configure what the bot does when a name filter is triggered. Requires 2FA.",
    )
    @commands.cooldown(1, 5, commands.BucketType.user)
    async def set_action(
        self,
        ctx: discord.ApplicationContext,
        action: Option(
            str,
            "Action to take on a match ('flag' = log only, moderators decide)",
            choices=['flag', 'ban', 'kick', 'timeout'],
            required=True,
        ),
        code: Option(int, "Your 6-digit 2FA code", required=True),
        timeout_hours: Option(
            int,
            "Hours to timeout for (only applies when action=timeout, default 24)",
            required=False,
            default=24,
            min_value=1,
            max_value=672,
        ),
    ):
        # Owner-gated: this decides whether a filter match kicks, times out, or
        # permanently bans. Announcers can maintain the pattern list, but not
        # escalate what a match does.
        allowed, err = permissions.check(self.bot, ctx, 'owner')
        if not allowed:
            await ctx.respond(err, ephemeral=True)
            return
        ok2, err2 = permissions.guild_required(self.bot, ctx)
        if not ok2:
            await ctx.respond(err2, ephemeral=True)
            return

        if not two_factor_helper.verify_code(self.bot.CONN, ctx.author.id, code):
            await ctx.respond("Incorrect 2FA code.", ephemeral=True)
            return

        stored = f"timeout:{timeout_hours}" if action == 'timeout' else action
        db_handler.set_name_filter_action(self.bot.CONN, ctx.guild.id, stored)

        label = f"Timeout ({timeout_hours}h)" if action == 'timeout' else _action_label(action)
        note = (
            "\nMatches will be **logged only** — no member is kicked or banned. "
            "Your moderators review the log and act."
            if action == 'flag' else
            "\nThis acts automatically and, for bans, cannot be undone in bulk. "
            "Test patterns with `/name-filter test` first."
        )
        await ctx.respond(
            f"Name filter action updated to **{label}**.\n"
            f"All future filter matches will result in: **{label}**.{note}",
            ephemeral=True,
        )
        await logger.log_action(
            self.bot, ctx.guild, "Name Filter Action Changed", ctx.author,
            details={"New Action": label},
            level='info',
        )

    # ------------------------------------------------------------------
    # /name-filter cleanse
    # ------------------------------------------------------------------

    @nf.command(
        name="cleanse",
        description="[Owner] Scan every current member against all active filters and action matches. Requires 2FA.",
    )
    @commands.cooldown(1, 300, commands.BucketType.guild)
    async def cleanse(
        self,
        ctx: discord.ApplicationContext,
        code: Option(int, "Your 6-digit 2FA code", required=True),
    ):
        # Owner-gated: this is a retroactive, irreversible, server-wide action.
        # A single loose pattern here can ban every non-exempt member, so it
        # sits at a higher level than the day-to-day filter management commands.
        allowed, err = permissions.check(self.bot, ctx, 'owner')
        if not allowed:
            await ctx.respond(err, ephemeral=True)
            return
        ok2, err2 = permissions.guild_required(self.bot, ctx)
        if not ok2:
            await ctx.respond(err2, ephemeral=True)
            return

        if not two_factor_helper.verify_code(self.bot.CONN, ctx.author.id, code):
            await ctx.respond("Incorrect 2FA code.", ephemeral=True)
            return

        filters = db_handler.get_name_filters(self.bot.CONN, ctx.guild.id)
        if not filters:
            await ctx.respond(
                "No filters configured. Add some with `/name-filter add` or `/name-filter import` first.",
                ephemeral=True,
            )
            return

        await ctx.defer(ephemeral=True)

        action   = db_handler.get_name_filter_action(self.bot.CONN, ctx.guild.id)
        actioned = 0
        failed   = 0
        skipped  = 0

        # ------------------------------------------------------------------
        # Phase 1 — work out who matches, without touching anyone yet.
        # ------------------------------------------------------------------
        matches = []
        for member in list(ctx.guild.members):
            if member.bot:
                continue
            if _is_exempt(self.bot, ctx.guild, member.id):
                skipped += 1
                continue

            # Check username first, then nickname
            matched_filter, matched_name = _match(filters, member.name)
            trigger = "Cleanse scan — username"

            if not matched_filter and member.nick:
                matched_filter, matched_name = _match(filters, member.nick)
                trigger = "Cleanse scan — nickname"

            if matched_filter:
                matches.append((member, matched_filter, matched_name, trigger))

        # ------------------------------------------------------------------
        # Phase 2 — refuse to run if the blast radius looks like a mistake.
        #
        # An over-broad pattern (a stray `.*`, an unescaped `.`) would other-
        # wise ban most of the server before anyone could react, and bans
        # cannot be undone in bulk. Bail out and make the operator narrow the
        # filter instead.
        # ------------------------------------------------------------------
        eligible = max(1, len([m for m in ctx.guild.members if not m.bot]) - skipped)
        share = len(matches) / eligible
        # 'flag' only writes log entries, so a wide match is noisy rather than
        # destructive — the guard exists to stop irreversible mass actions.
        if action != 'flag' and len(matches) > CLEANSE_ABORT_MIN and share > CLEANSE_ABORT_SHARE:
            preview = "\n".join(
                f"  • `{m.name}` — matched `{f['pattern']}` (filter #{f['id']})"
                for m, f, _, _ in matches[:10]
            )
            await ctx.followup.send(
                f"**Cleanse aborted — nothing was changed.**\n"
                f"**{len(matches)}** of **{eligible}** eligible members matched "
                f"({share:.0%}). That is above the {CLEANSE_ABORT_SHARE:.0%} safety "
                f"threshold and looks like an over-broad filter rather than a real "
                f"wave of bad accounts.\n\n"
                f"First matches:\n{preview}\n\n"
                f"Review your patterns with `/name-filter list`, test them with "
                f"`/name-filter test`, then run cleanse again.",
                ephemeral=True,
            )
            return

        # ------------------------------------------------------------------
        # Phase 3 — apply.
        # ------------------------------------------------------------------
        for member, matched_filter, matched_name, trigger in matches:
            try:
                await _take_action(
                    self.bot, ctx.guild, member, action,
                    matched_filter, matched_name, trigger,
                )
                actioned += 1
            except Exception:
                failed += 1
            # Brief pause between actions to avoid Discord rate limiting
            await asyncio.sleep(0.75)

        action_label = _action_label(action)
        verb = "flagged for review" if action == 'flag' else f"actioned ({action_label})"

        await ctx.followup.send(
            f"**Cleanse complete.**\n"
            f"**{actioned}** member(s) {verb} • "
            f"**{skipped}** exempt • "
            f"**{failed}** failed\n"
            f"Filters checked: **{len(filters)}** • "
            f"Full details logged to your log channel.",
            ephemeral=True,
        )

    # ------------------------------------------------------------------
    # Event: member joins
    # ------------------------------------------------------------------

    @commands.Cog.listener()
    async def on_member_join(self, member: discord.Member):
        if member.bot:
            return
        guild = member.guild
        if not db_handler.check_guild(self.bot.CONN, guild.id):
            return
        if _is_exempt(self.bot, guild, member.id):
            return

        filters = db_handler.get_name_filters(self.bot.CONN, guild.id)
        if not filters:
            return

        # Check username
        matched_filter, matched_name = _match(filters, member.name)
        trigger = "Joined server — username"

        # Also check display name if it differs (e.g. global display name set)
        if not matched_filter and member.display_name != member.name:
            matched_filter, matched_name = _match(filters, member.display_name)
            trigger = "Joined server — display name"

        if matched_filter:
            action = db_handler.get_name_filter_action(self.bot.CONN, guild.id)
            await _take_action(self.bot, guild, member, action, matched_filter, matched_name, trigger)

    # ------------------------------------------------------------------
    # Event: nickname change within the server
    # ------------------------------------------------------------------

    @commands.Cog.listener()
    async def on_member_update(self, before: discord.Member, after: discord.Member):
        if after.bot:
            return
        # Only care about nickname changes
        if before.nick == after.nick:
            return
        # Nickname was removed — not a threat
        if not after.nick:
            return

        guild = after.guild
        if not db_handler.check_guild(self.bot.CONN, guild.id):
            return
        if _is_exempt(self.bot, guild, after.id):
            return

        filters = db_handler.get_name_filters(self.bot.CONN, guild.id)
        if not filters:
            return

        matched_filter, matched_name = _match(filters, after.nick)
        if matched_filter:
            action = db_handler.get_name_filter_action(self.bot.CONN, guild.id)
            await _take_action(
                self.bot, guild, after, action,
                matched_filter, matched_name, "Changed their server nickname",
            )

    # ------------------------------------------------------------------
    # Event: global username change
    # ------------------------------------------------------------------

    @commands.Cog.listener()
    async def on_user_update(self, before: discord.User, after: discord.User):
        # Only care about name changes
        if before.name == after.name:
            return

        # Check the new username against every guild the bot shares with this user
        for guild in self.bot.guilds:
            if not db_handler.check_guild(self.bot.CONN, guild.id):
                continue
            member = guild.get_member(after.id)
            if not member or member.bot:
                continue
            if _is_exempt(self.bot, guild, member.id):
                continue

            filters = db_handler.get_name_filters(self.bot.CONN, guild.id)
            if not filters:
                continue

            matched_filter, matched_name = _match(filters, after.name)
            if matched_filter:
                action = db_handler.get_name_filter_action(self.bot.CONN, guild.id)
                await _take_action(
                    self.bot, guild, member, action,
                    matched_filter, matched_name, "Changed their global Discord username",
                )


def setup(bot):
    bot.add_cog(NameFilter(bot))
