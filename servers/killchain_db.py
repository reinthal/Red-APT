#!/usr/bin/env python3
"""
Kill Chain Database Server - Central Data Store for Red Team Operations

Stores all findings from each phase of the cyber kill chain in a unified
PostgreSQL database. Provides easy LLM access via full-text search on context.

Environment Variables:
    KC_POSTGRES_URL: PostgreSQL connection URL (default: postgresql://postgres:postgres@localhost:5432/killchain)

Schema:
- assets: Unified table for all findings (domains, IPs, software, users, files, etc.)
- Full-text search enabled via PostgreSQL tsvector on context column

Tools:
- kc_init: Initialize database for a session
- kc_add_asset: Add a finding/asset
- kc_search: Full-text search across all assets
- kc_list: List assets by type or session
- kc_get: Get specific asset by ID
- kc_update: Update an existing asset
- kc_delete: Delete an asset
- kc_stats: Get statistics for a session
- kc_export: Export session data as JSON
"""

import asyncio
import json
import os
from datetime import datetime
from typing import Optional, List
from contextlib import asynccontextmanager

from fastmcp import FastMCP

# Check for test mode
TEST_MODE = os.getenv("MCP_TEST_MODE", "false").lower() == "true"

mcp = FastMCP("killchain_db")

# ---------------------------------------------------------------------------
# Database Configuration
# ---------------------------------------------------------------------------

POSTGRES_URL = os.getenv(
    "KC_POSTGRES_URL",
    "postgresql://postgres:postgres@localhost:5432/killchain"
)

# Connection pool (initialized lazily)
_pool = None

async def get_pool():
    """Get or create the connection pool."""
    global _pool
    if _pool is None:
        import asyncpg
        _pool = await asyncpg.create_pool(
            POSTGRES_URL,
            min_size=2,
            max_size=10,
            command_timeout=60,
        )
    return _pool

async def close_pool():
    """Close the connection pool."""
    global _pool
    if _pool:
        await _pool.close()
        _pool = None

@asynccontextmanager
async def get_connection():
    """Get a connection from the pool."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        yield conn

async def init_database():
    """Initialize database schema."""
    async with get_connection() as conn:
        # Main assets table - unified storage for all finding types
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS assets (
                id SERIAL PRIMARY KEY,
                session_id TEXT NOT NULL,
                type TEXT NOT NULL,
                value TEXT NOT NULL,
                context TEXT,
                phase TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                search_vector TSVECTOR GENERATED ALWAYS AS (
                    to_tsvector('english', coalesce(value, '') || ' ' || coalesce(context, ''))
                ) STORED
            )
        """)

        # Create indexes for common queries
        await conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_assets_session ON assets(session_id)
        """)
        await conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_assets_type ON assets(type)
        """)
        await conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_assets_phase ON assets(phase)
        """)
        # GIN index for full-text search
        await conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_assets_search ON assets USING GIN(search_vector)
        """)

# ---------------------------------------------------------------------------
# Asset Types (for reference)
# ---------------------------------------------------------------------------

ASSET_TYPES = [
    "domain",      # Discovered domains/subdomains
    "ip",          # IP addresses
    "port",        # Open ports/services
    "software",    # Software/versions detected
    "user",        # Usernames/accounts
    "credential",  # Credentials found
    "file",        # Files of interest
    "email",       # Email addresses
    "url",         # URLs/endpoints
    "vuln",        # Vulnerabilities
    "config",      # Configuration findings
    "other",       # Miscellaneous
]

KILL_CHAIN_PHASES = [
    "recon",           # Reconnaissance
    "weaponization",   # Weaponization
    "delivery",        # Delivery
    "exploitation",    # Exploitation
    "installation",    # Installation
    "c2",              # Command & Control
    "actions",         # Actions on Objectives
]

# ---------------------------------------------------------------------------
# Test Mode Responses
# ---------------------------------------------------------------------------

FAKE_ASSETS = [
    {"id": 1, "session_id": "test-session", "type": "domain", "value": "target.com", "context": "Primary target domain discovered via DNS enumeration", "phase": "recon"},
    {"id": 2, "session_id": "test-session", "type": "ip", "value": "192.168.1.100", "context": "Web server IP resolved from target.com A record", "phase": "recon"},
    {"id": 3, "session_id": "test-session", "type": "port", "value": "443/tcp", "context": "HTTPS service running nginx 1.19.0", "phase": "recon"},
    {"id": 4, "session_id": "test-session", "type": "software", "value": "nginx/1.19.0", "context": "Web server version detected via banner grab", "phase": "recon"},
    {"id": 5, "session_id": "test-session", "type": "user", "value": "admin", "context": "Admin user found in /admin login page", "phase": "recon"},
]

# ---------------------------------------------------------------------------
# Helper to convert asyncpg Record to dict
# ---------------------------------------------------------------------------

def record_to_dict(record) -> dict:
    """Convert asyncpg Record to dictionary, handling datetime serialization."""
    d = dict(record)
    for k, v in d.items():
        if isinstance(v, datetime):
            d[k] = v.isoformat()
        # Skip the search_vector column
        if k == 'search_vector':
            del d[k]
    # Remove search_vector if present
    d.pop('search_vector', None)
    return d

# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------

@mcp.tool()
async def kc_init(session_id: str) -> str:
    """
    Initialize a new kill chain session.

    Args:
        session_id: Unique identifier for this operation/session

    Returns:
        Session initialization status
    """
    if TEST_MODE:
        return json.dumps({
            "success": True,
            "session_id": session_id,
            "message": f"[TEST MODE] Session '{session_id}' initialized",
            "backend": "postgresql",
        })

    try:
        await init_database()

        return json.dumps({
            "success": True,
            "session_id": session_id,
            "message": f"Session '{session_id}' ready",
            "backend": "postgresql",
            "asset_types": ASSET_TYPES,
            "phases": KILL_CHAIN_PHASES,
        })
    except Exception as e:
        return json.dumps({
            "success": False,
            "error": str(e),
        })


@mcp.tool()
async def kc_add_asset(
    session_id: str,
    asset_type: str,
    value: str,
    context: Optional[str] = None,
    phase: Optional[str] = None
) -> str:
    """
    Add a new asset/finding to the kill chain database.

    Args:
        session_id: Session identifier
        asset_type: Type of asset (domain, ip, port, software, user, credential, file, email, url, vuln, config, other)
        value: The actual value (e.g., "192.168.1.1", "admin", "target.com")
        context: Free-text description/context for LLM search (e.g., "Found via nmap scan on port 22")
        phase: Kill chain phase (recon, weaponization, delivery, exploitation, installation, c2, actions)

    Returns:
        Created asset details
    """
    if TEST_MODE:
        return json.dumps({
            "success": True,
            "id": 99,
            "session_id": session_id,
            "type": asset_type,
            "value": value,
            "context": context,
            "phase": phase,
            "message": "[TEST MODE] Asset added",
        })

    try:
        async with get_connection() as conn:
            row = await conn.fetchrow("""
                INSERT INTO assets (session_id, type, value, context, phase)
                VALUES ($1, $2, $3, $4, $5)
                RETURNING id, session_id, type, value, context, phase, created_at
            """, session_id, asset_type, value, context, phase)

            return json.dumps({
                "success": True,
                **record_to_dict(row),
            })
    except Exception as e:
        return json.dumps({
            "success": False,
            "error": str(e),
        })


@mcp.tool()
async def kc_search(
    query: str,
    session_id: Optional[str] = None,
    asset_type: Optional[str] = None,
    limit: int = 50
) -> str:
    """
    Full-text search across all assets. Searches value and context fields.

    Args:
        query: Search query (supports PostgreSQL tsquery syntax: & for AND, | for OR, ! for NOT)
        session_id: Filter by session (optional)
        asset_type: Filter by type (optional)
        limit: Maximum results (default: 50)

    Returns:
        Matching assets
    """
    if TEST_MODE:
        results = [a for a in FAKE_ASSETS if query.lower() in a["value"].lower() or query.lower() in a["context"].lower()]
        return json.dumps({
            "success": True,
            "query": query,
            "results": results[:limit],
            "count": len(results),
            "test_mode": True,
        })

    try:
        async with get_connection() as conn:
            # Build query with full-text search
            # Use plainto_tsquery for simple queries, websearch_to_tsquery for advanced
            sql = """
                SELECT id, session_id, type, value, context, phase, created_at, updated_at,
                       ts_rank(search_vector, query) as rank
                FROM assets, plainto_tsquery('english', $1) query
                WHERE search_vector @@ query
            """
            params = [query]
            param_idx = 2

            if session_id:
                sql += f" AND session_id = ${param_idx}"
                params.append(session_id)
                param_idx += 1

            if asset_type:
                sql += f" AND type = ${param_idx}"
                params.append(asset_type)
                param_idx += 1

            sql += f" ORDER BY rank DESC, created_at DESC LIMIT ${param_idx}"
            params.append(limit)

            rows = await conn.fetch(sql, *params)
            results = [record_to_dict(row) for row in rows]

            return json.dumps({
                "success": True,
                "query": query,
                "results": results,
                "count": len(results),
            })
    except Exception as e:
        return json.dumps({
            "success": False,
            "error": str(e),
            "query": query,
        })


@mcp.tool()
async def kc_list(
    session_id: str,
    asset_type: Optional[str] = None,
    phase: Optional[str] = None,
    limit: int = 100
) -> str:
    """
    List assets for a session, optionally filtered by type or phase.

    Args:
        session_id: Session identifier
        asset_type: Filter by type (optional)
        phase: Filter by kill chain phase (optional)
        limit: Maximum results (default: 100)

    Returns:
        List of assets
    """
    if TEST_MODE:
        results = [a for a in FAKE_ASSETS if a["session_id"] == session_id or session_id == "test-session"]
        if asset_type:
            results = [a for a in results if a["type"] == asset_type]
        if phase:
            results = [a for a in results if a["phase"] == phase]
        return json.dumps({
            "success": True,
            "session_id": session_id,
            "results": results[:limit],
            "count": len(results),
            "test_mode": True,
        })

    try:
        async with get_connection() as conn:
            sql = "SELECT id, session_id, type, value, context, phase, created_at, updated_at FROM assets WHERE session_id = $1"
            params = [session_id]
            param_idx = 2

            if asset_type:
                sql += f" AND type = ${param_idx}"
                params.append(asset_type)
                param_idx += 1

            if phase:
                sql += f" AND phase = ${param_idx}"
                params.append(phase)
                param_idx += 1

            sql += f" ORDER BY created_at DESC LIMIT ${param_idx}"
            params.append(limit)

            rows = await conn.fetch(sql, *params)
            results = [record_to_dict(row) for row in rows]

            return json.dumps({
                "success": True,
                "session_id": session_id,
                "results": results,
                "count": len(results),
            })
    except Exception as e:
        return json.dumps({
            "success": False,
            "error": str(e),
        })


@mcp.tool()
async def kc_get(asset_id: int) -> str:
    """
    Get a specific asset by ID.

    Args:
        asset_id: Asset ID

    Returns:
        Asset details
    """
    if TEST_MODE:
        for a in FAKE_ASSETS:
            if a["id"] == asset_id:
                return json.dumps({"success": True, "asset": a, "test_mode": True})
        return json.dumps({"success": False, "error": f"Asset {asset_id} not found"})

    try:
        async with get_connection() as conn:
            row = await conn.fetchrow(
                "SELECT id, session_id, type, value, context, phase, created_at, updated_at FROM assets WHERE id = $1",
                asset_id
            )

            if row:
                return json.dumps({
                    "success": True,
                    "asset": record_to_dict(row),
                })
            else:
                return json.dumps({
                    "success": False,
                    "error": f"Asset {asset_id} not found",
                })
    except Exception as e:
        return json.dumps({
            "success": False,
            "error": str(e),
        })


@mcp.tool()
async def kc_update(
    asset_id: int,
    value: Optional[str] = None,
    context: Optional[str] = None,
    phase: Optional[str] = None,
    asset_type: Optional[str] = None
) -> str:
    """
    Update an existing asset.

    Args:
        asset_id: Asset ID to update
        value: New value (optional)
        context: New context (optional)
        phase: New phase (optional)
        asset_type: New type (optional)

    Returns:
        Updated asset details
    """
    if TEST_MODE:
        return json.dumps({
            "success": True,
            "id": asset_id,
            "message": "[TEST MODE] Asset updated",
        })

    try:
        async with get_connection() as conn:
            # Build update query dynamically
            updates = []
            params = []
            param_idx = 1

            if value is not None:
                updates.append(f"value = ${param_idx}")
                params.append(value)
                param_idx += 1
            if context is not None:
                updates.append(f"context = ${param_idx}")
                params.append(context)
                param_idx += 1
            if phase is not None:
                updates.append(f"phase = ${param_idx}")
                params.append(phase)
                param_idx += 1
            if asset_type is not None:
                updates.append(f"type = ${param_idx}")
                params.append(asset_type)
                param_idx += 1

            if not updates:
                return json.dumps({
                    "success": False,
                    "error": "No fields to update",
                })

            updates.append("updated_at = CURRENT_TIMESTAMP")
            params.append(asset_id)

            sql = f"""
                UPDATE assets SET {', '.join(updates)}
                WHERE id = ${param_idx}
                RETURNING id, session_id, type, value, context, phase, created_at, updated_at
            """

            row = await conn.fetchrow(sql, *params)

            if row:
                return json.dumps({
                    "success": True,
                    "asset": record_to_dict(row),
                })
            else:
                return json.dumps({
                    "success": False,
                    "error": f"Asset {asset_id} not found",
                })
    except Exception as e:
        return json.dumps({
            "success": False,
            "error": str(e),
        })


@mcp.tool()
async def kc_delete(asset_id: int) -> str:
    """
    Delete an asset.

    Args:
        asset_id: Asset ID to delete

    Returns:
        Deletion status
    """
    if TEST_MODE:
        return json.dumps({
            "success": True,
            "id": asset_id,
            "message": "[TEST MODE] Asset deleted",
        })

    try:
        async with get_connection() as conn:
            result = await conn.execute("DELETE FROM assets WHERE id = $1", asset_id)

            # result is like "DELETE 1" or "DELETE 0"
            count = int(result.split()[-1])

            if count == 0:
                return json.dumps({
                    "success": False,
                    "error": f"Asset {asset_id} not found",
                })

            return json.dumps({
                "success": True,
                "id": asset_id,
                "message": "Asset deleted",
            })
    except Exception as e:
        return json.dumps({
            "success": False,
            "error": str(e),
        })


@mcp.tool()
async def kc_stats(session_id: str) -> str:
    """
    Get statistics for a session.

    Args:
        session_id: Session identifier

    Returns:
        Session statistics (counts by type, phase, etc.)
    """
    if TEST_MODE:
        return json.dumps({
            "success": True,
            "session_id": session_id,
            "total_assets": 5,
            "by_type": {"domain": 1, "ip": 1, "port": 1, "software": 1, "user": 1},
            "by_phase": {"recon": 5},
            "test_mode": True,
        })

    try:
        async with get_connection() as conn:
            # Total count
            total = await conn.fetchval(
                "SELECT COUNT(*) FROM assets WHERE session_id = $1",
                session_id
            )

            # Count by type
            type_rows = await conn.fetch("""
                SELECT type, COUNT(*) as count
                FROM assets WHERE session_id = $1
                GROUP BY type
            """, session_id)
            by_type = {row["type"]: row["count"] for row in type_rows}

            # Count by phase
            phase_rows = await conn.fetch("""
                SELECT phase, COUNT(*) as count
                FROM assets WHERE session_id = $1 AND phase IS NOT NULL
                GROUP BY phase
            """, session_id)
            by_phase = {row["phase"]: row["count"] for row in phase_rows}

            # Recent assets
            recent_rows = await conn.fetch("""
                SELECT id, session_id, type, value, context, phase, created_at, updated_at
                FROM assets WHERE session_id = $1
                ORDER BY created_at DESC LIMIT 5
            """, session_id)
            recent = [record_to_dict(row) for row in recent_rows]

            return json.dumps({
                "success": True,
                "session_id": session_id,
                "total_assets": total,
                "by_type": by_type,
                "by_phase": by_phase,
                "recent": recent,
            })
    except Exception as e:
        return json.dumps({
            "success": False,
            "error": str(e),
        })


@mcp.tool()
async def kc_export(
    session_id: str,
    format: str = "json"
) -> str:
    """
    Export all session data.

    Args:
        session_id: Session identifier
        format: Export format (json, csv, markdown)

    Returns:
        Exported data
    """
    if TEST_MODE:
        return json.dumps({
            "success": True,
            "session_id": session_id,
            "format": format,
            "data": FAKE_ASSETS,
            "test_mode": True,
        })

    try:
        async with get_connection() as conn:
            rows = await conn.fetch("""
                SELECT id, session_id, type, value, context, phase, created_at, updated_at
                FROM assets WHERE session_id = $1
                ORDER BY phase, type, created_at
            """, session_id)

            assets = [record_to_dict(row) for row in rows]

            if format == "csv":
                if not assets:
                    output = "id,session_id,type,value,context,phase,created_at,updated_at\n"
                else:
                    header = ",".join(assets[0].keys())
                    lines = [header]
                    for a in assets:
                        line = ",".join(f'"{v}"' if v else '""' for v in a.values())
                        lines.append(line)
                    output = "\n".join(lines)

                return json.dumps({
                    "success": True,
                    "session_id": session_id,
                    "format": "csv",
                    "data": output,
                    "count": len(assets),
                })

            elif format == "markdown":
                lines = [f"# Kill Chain Report: {session_id}\n"]

                # Group by phase
                phases = {}
                for a in assets:
                    p = a.get("phase") or "unclassified"
                    if p not in phases:
                        phases[p] = []
                    phases[p].append(a)

                for phase in KILL_CHAIN_PHASES + ["unclassified"]:
                    if phase in phases:
                        lines.append(f"\n## {phase.title()}\n")
                        for a in phases[phase]:
                            lines.append(f"- **[{a['type']}]** `{a['value']}`")
                            if a.get("context"):
                                lines.append(f"  - {a['context']}")

                return json.dumps({
                    "success": True,
                    "session_id": session_id,
                    "format": "markdown",
                    "data": "\n".join(lines),
                    "count": len(assets),
                })

            else:  # json
                return json.dumps({
                    "success": True,
                    "session_id": session_id,
                    "format": "json",
                    "data": assets,
                    "count": len(assets),
                })
    except Exception as e:
        return json.dumps({
            "success": False,
            "error": str(e),
        })


@mcp.tool()
async def kc_bulk_add(
    session_id: str,
    assets: str
) -> str:
    """
    Add multiple assets at once (uses transaction for atomicity).

    Args:
        session_id: Session identifier
        assets: JSON array of assets, each with: type, value, context (optional), phase (optional)

    Returns:
        Bulk insert results
    """
    if TEST_MODE:
        return json.dumps({
            "success": True,
            "session_id": session_id,
            "inserted": 5,
            "message": "[TEST MODE] Bulk insert complete",
        })

    try:
        asset_list = json.loads(assets)

        if not isinstance(asset_list, list):
            return json.dumps({
                "success": False,
                "error": "Assets must be a JSON array",
            })

        async with get_connection() as conn:
            # Use a transaction for atomic bulk insert
            async with conn.transaction():
                inserted = 0
                for asset in asset_list:
                    await conn.execute("""
                        INSERT INTO assets (session_id, type, value, context, phase)
                        VALUES ($1, $2, $3, $4, $5)
                    """,
                        session_id,
                        asset.get("type", "other"),
                        asset.get("value", ""),
                        asset.get("context"),
                        asset.get("phase"),
                    )
                    inserted += 1

                return json.dumps({
                    "success": True,
                    "session_id": session_id,
                    "inserted": inserted,
                })
    except json.JSONDecodeError as e:
        return json.dumps({
            "success": False,
            "error": f"Invalid JSON: {str(e)}",
        })
    except Exception as e:
        return json.dumps({
            "success": False,
            "error": str(e),
        })


if __name__ == "__main__":
    mcp.run()
