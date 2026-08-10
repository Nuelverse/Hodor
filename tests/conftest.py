"""
Shared pytest fixtures.

Provides:
  - in_memory_db: a fresh SQLite connection (in-memory) with all tables created
  - mock_bot:     a minimal bot-like object with CONN and master_user for permission tests
  - mock_ctx:     a factory for creating mock Discord ApplicationContext objects
"""

import sqlite3
import types
import pytest
import sys
import os

# Ensure the project root is importable
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import db_handler


@pytest.fixture
def in_memory_db():
    """
    Returns a real SQLite connection (in-memory) with all tables and migrations applied.
    Each test gets a completely fresh database.
    """
    conn = sqlite3.connect(":memory:")

    # Foreign keys OFF deliberately. These are unit tests over individual
    # tables, and most insert child rows (trusted_members, channel_table)
    # without first creating the parent guild. The previous fixture had the
    # same effective behaviour: it declared PRAGMA foreign_keys=ON but its
    # hand-copied schema omitted every FK clause, so nothing was enforced.
    #
    # Known gap: production runs with foreign_keys=ON, so referential
    # integrity is not covered here. Worth closing separately by seeding a
    # guild in the affected tests.
    conn.execute("PRAGMA foreign_keys=OFF")

    # Build from the real schema in db_handler rather than a copy. The previous
    # hand-maintained duplicate drifted every time a table was added, so tests
    # failed for fixture reasons that looked like product bugs.
    db_handler.create_schema(conn)

    # db_handler caches guild config keyed by connection identity; a recycled
    # id() from a closed connection could otherwise serve stale rows to a
    # later test.
    db_handler.clear_cache()
    yield conn
    db_handler.clear_cache()
    conn.close()


@pytest.fixture
def mock_bot(in_memory_db):
    """Minimal bot-like namespace with CONN and master_user."""
    bot = types.SimpleNamespace()
    bot.CONN = in_memory_db
    bot.master_user = 999999999999999999  # Arbitrary bot owner ID
    return bot


def _make_mock_ctx(guild_id: int, author_id: int, guild_owner_id: int = 111111111111111111):
    """Create a minimal mock ApplicationContext-like object."""
    guild = types.SimpleNamespace()
    guild.id = guild_id
    guild.owner_id = guild_owner_id

    author = types.SimpleNamespace()
    author.id = author_id

    ctx = types.SimpleNamespace()
    ctx.guild = guild
    ctx.author = author
    return ctx


@pytest.fixture
def make_ctx():
    """Factory fixture for creating mock contexts."""
    return _make_mock_ctx
