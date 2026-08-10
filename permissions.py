"""
Permission helpers for SecurityBot.

THE MODEL — "locksmith, not landlord"
-------------------------------------
The bot is designed to run in servers its operator does not own, so authority
is split by *scope* rather than by seniority:

  GLOBAL OPERATOR (MASTER_USER_ID in .env)
      The person who hosts the bot. Holds the emergency hatch — panic and
      recover by DM — so a server can be rescued even after the operator has
      been kicked from it (the bot only needs to still be in the guild; the
      operator does not). Deliberately NOT the day-to-day authority: a client
      must never depend on the operator being awake to run their own server.

  SERVER OWNER (guild.owner_id)
      Full authority over their own server: setup, configuration, granting
      keycards, and the destructive commands. Everything needed to operate
      without the global operator.

  LINK MANAGER — registered + 2FA verified + in link_managers table
  ANNOUNCER    — registered + 2FA verified + in trusted_members table

Rules:
  - No user can run a command unless they are at least one of the above.
  - /create-2fa is available to bot owner, server owner, or any registered user.
  - 2FA is required for all security-sensitive operations.
  - The global operator also passes every 'owner' check, so it can still
    support a server hands-on when asked. The difference is that the server
    owner is never blocked waiting for it.
"""

import db_handler


def is_bot_owner(bot, user_id: int) -> bool:
    return user_id == bot.master_user


def is_server_owner(ctx) -> bool:
    return ctx.author.id == ctx.guild.owner_id


def is_2fa_ready(bot, user_id: int) -> bool:
    """User has a registered and verified 2FA account."""
    return (
        db_handler.check_user(bot.CONN, user_id)
        and db_handler.check_verified(bot.CONN, user_id) == 1
    )


def is_link_manager(bot, guild_id: int, user_id: int) -> bool:
    return db_handler.is_link_manager(bot.CONN, guild_id, user_id)


def is_announcer(bot, guild_id: int, user_id: int) -> bool:
    return db_handler.check_authorised(bot.CONN, (guild_id, user_id))


def is_registered(bot, guild_id: int, user_id: int) -> bool:
    """User is in at least one of the roles (link manager or announcer)."""
    return (
        is_link_manager(bot, guild_id, user_id)
        or is_announcer(bot, guild_id, user_id)
    )


def is_elevated(bot, ctx) -> bool:
    """Bot owner or server owner."""
    return is_bot_owner(bot, ctx.author.id) or is_server_owner(ctx)


def can_setup_2fa(bot, ctx) -> bool:
    """
    /create-2fa is allowed for: bot owner, server owner, or any registered user.
    Prevents random users from self-enrolling.
    """
    uid = ctx.author.id
    return (
        is_bot_owner(bot, uid)
        or is_server_owner(ctx)
        or is_registered(bot, ctx.guild.id, uid)
    )


def check(bot, ctx, level: str) -> tuple[bool, str]:
    """
    Central permission gate. Returns (allowed, error_message).

    Levels:
      'bot_owner'      — MASTER_USER_ID only, 2FA required. Reserved for the
                         emergency hatch; prefer 'owner' so a server is never
                         blocked waiting for the global operator.
      'owner'          — bot owner OR server owner, 2FA required
      'owner_no_2fa'   — bot owner OR server owner, no 2FA check
      'link_manager'   — link managers + elevated users, 2FA required
      'announcer'      — announcers + elevated users, 2FA required
      'any_registered' — anyone in a role OR elevated (no 2FA check here)
    """
    uid = ctx.author.id
    gid = ctx.guild.id

    if level == 'bot_owner':
        if not is_bot_owner(bot, uid):
            return False, "Only the bot owner can use this command."
        if not is_2fa_ready(bot, uid):
            return False, "Complete `/create-2fa` and `/verify` first."
        return True, ""

    if level == 'owner':
        if not (is_bot_owner(bot, uid) or is_server_owner(ctx)):
            return False, "This command requires server owner or bot owner access."
        if not is_2fa_ready(bot, uid):
            return False, "Complete `/create-2fa` and `/verify` first."
        return True, ""

    if level == 'owner_no_2fa':
        if not (is_bot_owner(bot, uid) or is_server_owner(ctx)):
            return False, "This command requires server owner or bot owner access."
        return True, ""

    if level == 'link_manager':
        if is_bot_owner(bot, uid) or is_server_owner(ctx):
            if not is_2fa_ready(bot, uid):
                return False, "Complete `/create-2fa` and `/verify` first."
            return True, ""
        if not is_link_manager(bot, gid, uid):
            return False, "You must be a link manager to use this command."
        if not is_2fa_ready(bot, uid):
            return False, "Complete `/create-2fa` and `/verify` first."
        return True, ""

    if level == 'announcer':
        if is_bot_owner(bot, uid) or is_server_owner(ctx):
            if not is_2fa_ready(bot, uid):
                return False, "Complete `/create-2fa` and `/verify` first."
            return True, ""
        if not is_announcer(bot, gid, uid):
            return False, "You must be an announcer to use this command."
        if not is_2fa_ready(bot, uid):
            return False, "Complete `/create-2fa` and `/verify` first."
        return True, ""

    if level == 'any_registered':
        if is_bot_owner(bot, uid) or is_server_owner(ctx):
            return True, ""
        if not is_registered(bot, gid, uid):
            return False, "You must be registered as an announcer or link manager to use this command."
        return True, ""

    return True, ""


def guild_required(bot, ctx) -> tuple[bool, str]:
    """Check the guild is initialized in the DB."""
    if not db_handler.check_guild(bot.CONN, ctx.guild.id):
        return False, "This server has not been set up yet. Run `/setup-guild`."
    return True, ""
