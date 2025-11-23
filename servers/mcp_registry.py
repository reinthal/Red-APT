#!/usr/bin/env python3
"""
MCP Registry Server - Centralized Tool Management

A single MCP server that acts as a gateway to all other MCP servers.
Provides intelligent tool loading/eviction for context preservation.

The agent connects ONLY to this registry, which manages:
- Dynamic server connections
- Tool discovery and proxying
- Context-aware loading/eviction
- Usage tracking and optimization
"""

import asyncio
import json
import os
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml
from fastmcp import FastMCP
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

# Import thermal context management
from thermal_context import (
    ThermalContextManager,
    PredictiveThermalManager,
    ThermalTier,
    ContextItemType,
    THERMAL_TOOL_STRATEGIES,
    lazy_greedy_selection,
    lazy_greedy_with_saturation,
)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

SERVERS_DIR = Path(__file__).parent
CONFIG_PATH = SERVERS_DIR / "registry_config.yaml"

# Default context budget (in approximate token count for tool schemas)
DEFAULT_CONTEXT_BUDGET = 8000
TOKENS_PER_TOOL_ESTIMATE = 150  # Rough estimate per tool schema

# ---------------------------------------------------------------------------
# Data Structures
# ---------------------------------------------------------------------------

@dataclass
class ServerMetadata:
    """Metadata about a registered server."""
    name: str
    module: str
    description: str
    category: str = "general"
    priority: int = 5  # 1-10, higher = more important
    tools: List[str] = field(default_factory=list)
    estimated_tokens: int = 0


@dataclass
class LoadedServer:
    """A currently loaded server with its session."""
    metadata: ServerMetadata
    session: ClientSession
    read_stream: Any
    write_stream: Any
    process: Any
    loaded_at: float = field(default_factory=time.time)
    last_used: float = field(default_factory=time.time)
    call_count: int = 0


@dataclass
class ToolMapping:
    """Maps a tool to its server."""
    tool_name: str
    original_name: str
    server_name: str
    schema: Dict[str, Any]
    call_count: int = 0
    last_used: float = 0


@dataclass
class RegistryState:
    """Global state for the registry."""
    # Server registry
    available_servers: Dict[str, ServerMetadata] = field(default_factory=dict)
    loaded_servers: Dict[str, LoadedServer] = field(default_factory=dict)

    # Tool registry
    tool_mappings: Dict[str, ToolMapping] = field(default_factory=dict)

    # Context management
    context_budget: int = DEFAULT_CONTEXT_BUDGET
    current_context_usage: int = 0

    # Statistics
    total_calls: int = 0
    server_load_count: int = 0
    server_evict_count: int = 0

    # Configuration
    auto_evict: bool = True
    lazy_load: bool = True


# Global state
state = RegistryState()

# Thermal context manager for advanced lifecycle management
thermal_manager = PredictiveThermalManager(global_token_budget=50000)

# Current thermal tier for tool loading strategies
current_thermal_tier = "WARM"

# FastMCP instance
mcp = FastMCP("mcp-registry")

# ---------------------------------------------------------------------------
# Configuration Loading
# ---------------------------------------------------------------------------

def load_registry_config() -> Dict[str, Any]:
    """Load registry configuration from YAML file."""
    if CONFIG_PATH.exists():
        with open(CONFIG_PATH) as f:
            return yaml.safe_load(f) or {}
    return {}


def get_default_servers() -> Dict[str, Dict[str, Any]]:
    """Get default server definitions."""
    return {
        # === Security/Recon Servers ===
        "network": {
            "module": "recon_network.py",
            "description": "Network reconnaissance - IP/port scanning, service detection, traceroute",
            "category": "recon",
            "priority": 7,
        },
        "subdomain": {
            "module": "recon_subdomain.py",
            "description": "Subdomain enumeration - DNS lookups, CT logs, zone transfers",
            "category": "recon",
            "priority": 6,
        },
        "web": {
            "module": "recon_web.py",
            "description": "Web reconnaissance - directory enumeration, tech detection, headers",
            "category": "recon",
            "priority": 7,
        },
        "osint": {
            "module": "recon_osint.py",
            "description": "OSINT - email harvesting, username search, social media",
            "category": "recon",
            "priority": 5,
        },
        "evasion": {
            "module": "payload_evasion.py",
            "description": "Payload encoding and evasion testing",
            "category": "payload",
            "priority": 4,
        },
        "control": {
            "module": "agent_control.py",
            "description": "Agent control - system prompt mutation, refusal detection",
            "category": "control",
            "priority": 8,
        },
        # === Development/Productivity Servers ===
        "terminal": {
            "module": "terminal_server.py",
            "description": "Shell execution - commands, background processes, environment",
            "category": "dev",
            "priority": 9,
        },
        "filesystem": {
            "module": "filesystem_server.py",
            "description": "File operations - read, write, edit, search, glob",
            "category": "dev",
            "priority": 9,
        },
        "packages": {
            "module": "package_server.py",
            "description": "Package management - uv, pip, npm, virtual environments",
            "category": "dev",
            "priority": 7,
        },
        "code": {
            "module": "code_server.py",
            "description": "Code tools - templates, formatting, linting, imports",
            "category": "dev",
            "priority": 8,
        },
        "git": {
            "module": "git_server.py",
            "description": "Version control - status, diff, commit, push, branches",
            "category": "dev",
            "priority": 8,
        },
        "project": {
            "module": "project_server.py",
            "description": "Project scaffolding - templates, build, test, docker",
            "category": "dev",
            "priority": 6,
        },
    }


def initialize_registry():
    """Initialize the registry with available servers."""
    config = load_registry_config()
    servers = config.get("servers", get_default_servers())

    for name, info in servers.items():
        state.available_servers[name] = ServerMetadata(
            name=name,
            module=info.get("module", f"{name}.py"),
            description=info.get("description", ""),
            category=info.get("category", "general"),
            priority=info.get("priority", 5),
        )

    # Load context budget from config
    state.context_budget = config.get("context_budget", DEFAULT_CONTEXT_BUDGET)
    state.auto_evict = config.get("auto_evict", True)
    state.lazy_load = config.get("lazy_load", True)


# ---------------------------------------------------------------------------
# Server Management (Internal)
# ---------------------------------------------------------------------------

async def _connect_to_server(server_name: str) -> Optional[LoadedServer]:
    """Internal: Connect to an MCP server."""
    if server_name not in state.available_servers:
        return None

    if server_name in state.loaded_servers:
        return state.loaded_servers[server_name]

    metadata = state.available_servers[server_name]
    module_path = SERVERS_DIR / metadata.module

    if not module_path.exists():
        return None

    params = StdioServerParameters(
        command=sys.executable,
        args=[str(module_path)],
    )

    try:
        # Create the connection
        read_stream, write_stream = await stdio_client(params).__aenter__()
        session = ClientSession(read_stream, write_stream)
        await session.__aenter__()
        await session.initialize()

        # Get tools from this server
        tools_response = await session.list_tools()
        tool_names = []
        estimated_tokens = 0

        for tool in tools_response.tools:
            tool_name = tool.name
            # Prefix with server name to avoid conflicts
            prefixed_name = f"{server_name}__{tool.name}"

            schema = {
                "type": "function",
                "function": {
                    "name": prefixed_name,
                    "description": f"[{server_name}] {getattr(tool, 'description', '')}",
                    "parameters": {
                        "type": "object",
                        "properties": tool.inputSchema.get("properties", {}),
                        "required": tool.inputSchema.get("required", []),
                    },
                },
            }

            state.tool_mappings[prefixed_name] = ToolMapping(
                tool_name=prefixed_name,
                original_name=tool.name,
                server_name=server_name,
                schema=schema,
            )
            tool_names.append(prefixed_name)
            estimated_tokens += TOKENS_PER_TOOL_ESTIMATE

        metadata.tools = tool_names
        metadata.estimated_tokens = estimated_tokens

        loaded = LoadedServer(
            metadata=metadata,
            session=session,
            read_stream=read_stream,
            write_stream=write_stream,
            process=None,
        )

        state.loaded_servers[server_name] = loaded
        state.current_context_usage += estimated_tokens
        state.server_load_count += 1

        return loaded

    except Exception as e:
        print(f"[Registry] Failed to connect to {server_name}: {e}", file=sys.stderr)
        return None


async def _disconnect_server(server_name: str) -> bool:
    """Internal: Disconnect from an MCP server."""
    if server_name not in state.loaded_servers:
        return False

    loaded = state.loaded_servers[server_name]

    try:
        await loaded.session.__aexit__(None, None, None)
    except Exception:
        pass

    # Remove tool mappings
    for tool_name in loaded.metadata.tools:
        if tool_name in state.tool_mappings:
            del state.tool_mappings[tool_name]

    state.current_context_usage -= loaded.metadata.estimated_tokens
    del state.loaded_servers[server_name]
    state.server_evict_count += 1

    return True


async def _evict_for_context(needed_tokens: int) -> bool:
    """Evict servers to free up context budget."""
    if not state.auto_evict:
        return False

    # Sort loaded servers by priority (low first) then by last_used (oldest first)
    candidates = sorted(
        state.loaded_servers.values(),
        key=lambda s: (s.metadata.priority, s.last_used)
    )

    freed = 0
    for server in candidates:
        if state.current_context_usage + needed_tokens - freed <= state.context_budget:
            break

        await _disconnect_server(server.metadata.name)
        freed += server.metadata.estimated_tokens

    return freed >= needed_tokens


# ---------------------------------------------------------------------------
# Registry Tools (Exposed to Agent)
# ---------------------------------------------------------------------------

@mcp.tool()
async def list_available_servers() -> str:
    """
    List all servers registered in the MCP registry.

    Shows both loaded and unloaded servers with their metadata.
    Use this to discover what capabilities are available.
    """
    result = {
        "available_servers": [],
        "loaded_servers": list(state.loaded_servers.keys()),
        "context_usage": {
            "current": state.current_context_usage,
            "budget": state.context_budget,
            "percentage": round(state.current_context_usage / state.context_budget * 100, 1),
        },
    }

    for name, meta in state.available_servers.items():
        is_loaded = name in state.loaded_servers
        server_info = {
            "name": name,
            "description": meta.description,
            "category": meta.category,
            "priority": meta.priority,
            "loaded": is_loaded,
        }
        if is_loaded:
            loaded = state.loaded_servers[name]
            server_info["tools_count"] = len(meta.tools)
            server_info["call_count"] = loaded.call_count
        result["available_servers"].append(server_info)

    return json.dumps(result, indent=2)


@mcp.tool()
async def load_server(server_name: str) -> str:
    """
    Load an MCP server and make its tools available.

    Args:
        server_name: Name of the server to load (e.g., "network", "web", "osint")

    The server's tools will be added to the available tool set.
    Use list_available_servers() first to see what's available.
    """
    if server_name not in state.available_servers:
        return json.dumps({
            "success": False,
            "error": f"Unknown server: {server_name}",
            "available": list(state.available_servers.keys()),
        })

    if server_name in state.loaded_servers:
        loaded = state.loaded_servers[server_name]
        return json.dumps({
            "success": True,
            "message": f"Server '{server_name}' already loaded",
            "tools": loaded.metadata.tools,
        })

    # Check context budget
    meta = state.available_servers[server_name]
    estimated_tokens = len(get_default_servers().get(server_name, {}).get("tools", [])) * TOKENS_PER_TOOL_ESTIMATE
    if estimated_tokens == 0:
        estimated_tokens = 5 * TOKENS_PER_TOOL_ESTIMATE  # Default estimate

    if state.current_context_usage + estimated_tokens > state.context_budget:
        # Try to evict
        if not await _evict_for_context(estimated_tokens):
            return json.dumps({
                "success": False,
                "error": "Context budget exceeded. Unload some servers first.",
                "current_usage": state.current_context_usage,
                "budget": state.context_budget,
                "needed": estimated_tokens,
            })

    loaded = await _connect_to_server(server_name)
    if loaded:
        return json.dumps({
            "success": True,
            "message": f"Server '{server_name}' loaded successfully",
            "tools": loaded.metadata.tools,
            "context_used": loaded.metadata.estimated_tokens,
        })
    else:
        return json.dumps({
            "success": False,
            "error": f"Failed to connect to server '{server_name}'",
        })


@mcp.tool()
async def unload_server(server_name: str) -> str:
    """
    Unload an MCP server to free up context budget.

    Args:
        server_name: Name of the server to unload

    The server's tools will be removed from the available tool set.
    """
    if server_name not in state.loaded_servers:
        return json.dumps({
            "success": False,
            "error": f"Server '{server_name}' is not loaded",
            "loaded_servers": list(state.loaded_servers.keys()),
        })

    tokens_freed = state.loaded_servers[server_name].metadata.estimated_tokens
    success = await _disconnect_server(server_name)

    return json.dumps({
        "success": success,
        "message": f"Server '{server_name}' unloaded",
        "context_freed": tokens_freed,
        "current_usage": state.current_context_usage,
    })


@mcp.tool()
async def get_loaded_tools() -> str:
    """
    List all currently loaded tools across all loaded servers.

    Returns tool names, descriptions, and which server they belong to.
    """
    tools_by_server = {}

    for tool_name, mapping in state.tool_mappings.items():
        server = mapping.server_name
        if server not in tools_by_server:
            tools_by_server[server] = []

        tools_by_server[server].append({
            "name": tool_name,
            "original_name": mapping.original_name,
            "description": mapping.schema["function"].get("description", "")[:100],
            "call_count": mapping.call_count,
        })

    return json.dumps({
        "total_tools": len(state.tool_mappings),
        "tools_by_server": tools_by_server,
        "context_usage": state.current_context_usage,
    }, indent=2)


@mcp.tool()
async def call_tool(tool_name: str, arguments: str = "{}") -> str:
    """
    Execute a tool from a loaded server.

    Args:
        tool_name: Full tool name (e.g., "network__port_scan")
        arguments: JSON string of arguments to pass to the tool

    Use get_loaded_tools() to see available tools.
    """
    if tool_name not in state.tool_mappings:
        # Check if it's a short name
        for full_name, mapping in state.tool_mappings.items():
            if mapping.original_name == tool_name:
                tool_name = full_name
                break
        else:
            return json.dumps({
                "success": False,
                "error": f"Unknown tool: {tool_name}",
                "hint": "Use get_loaded_tools() to see available tools",
            })

    mapping = state.tool_mappings[tool_name]
    server_name = mapping.server_name

    if server_name not in state.loaded_servers:
        return json.dumps({
            "success": False,
            "error": f"Server '{server_name}' is not loaded",
        })

    try:
        args = json.loads(arguments) if isinstance(arguments, str) else arguments
    except json.JSONDecodeError:
        return json.dumps({
            "success": False,
            "error": "Invalid JSON in arguments",
        })

    loaded = state.loaded_servers[server_name]

    try:
        # Update usage stats
        loaded.last_used = time.time()
        loaded.call_count += 1
        mapping.call_count += 1
        mapping.last_used = time.time()
        state.total_calls += 1

        # Execute the tool
        response = await loaded.session.call_tool(mapping.original_name, args)

        # Extract content
        if hasattr(response, "content"):
            content = response.content
            if isinstance(content, list) and len(content) > 0:
                if hasattr(content[0], "text"):
                    result = content[0].text
                else:
                    result = str(content[0])
            else:
                result = str(content)
        else:
            result = str(response)

        return result

    except Exception as e:
        return json.dumps({
            "success": False,
            "error": str(e),
            "tool": tool_name,
        })


@mcp.tool()
async def suggest_servers(task_description: str) -> str:
    """
    Suggest which servers to load based on a task description.

    Args:
        task_description: Description of what you're trying to accomplish

    Returns recommended servers based on the task.
    """
    task_lower = task_description.lower()

    suggestions = []

    # Keyword matching for suggestions
    keywords = {
        # Security/Recon servers
        "network": ["port", "scan", "ip", "network", "service", "nmap", "traceroute", "host"],
        "subdomain": ["subdomain", "dns", "domain", "enumerate", "certificate", "ct log"],
        "web": ["web", "directory", "http", "url", "technology", "header", "wayback", "robots"],
        "osint": ["osint", "email", "username", "social", "harvest", "linkedin", "twitter", "github"],
        "evasion": ["payload", "encode", "obfuscate", "evasion", "bypass", "detection", "av"],
        "control": ["prompt", "mutation", "refusal", "jailbreak", "system prompt", "agent"],
        # Development servers
        "terminal": ["shell", "bash", "command", "execute", "run", "process", "terminal", "environment"],
        "filesystem": ["file", "read", "write", "edit", "directory", "folder", "search", "glob", "find"],
        "packages": ["install", "package", "pip", "uv", "npm", "dependency", "venv", "requirements"],
        "code": ["code", "template", "format", "lint", "import", "create", "generate", "python", "typescript"],
        "git": ["git", "commit", "push", "pull", "branch", "merge", "diff", "status", "version control"],
        "project": ["project", "scaffold", "build", "test", "docker", "init", "setup", "create project"],
    }

    for server, kws in keywords.items():
        matches = sum(1 for kw in kws if kw in task_lower)
        if matches > 0:
            meta = state.available_servers.get(server)
            if meta:
                suggestions.append({
                    "server": server,
                    "relevance": matches,
                    "description": meta.description,
                    "loaded": server in state.loaded_servers,
                    "priority": meta.priority,
                })

    # Sort by relevance then priority
    suggestions.sort(key=lambda x: (-x["relevance"], -x["priority"]))

    return json.dumps({
        "task": task_description,
        "suggestions": suggestions[:3],  # Top 3
        "all_servers": list(state.available_servers.keys()),
    }, indent=2)


@mcp.tool()
async def get_context_status() -> str:
    """
    Get current context budget usage and statistics.

    Shows how much context is being used by loaded servers
    and overall registry statistics.
    """
    server_usage = []
    for name, loaded in state.loaded_servers.items():
        server_usage.append({
            "server": name,
            "tokens": loaded.metadata.estimated_tokens,
            "tools": len(loaded.metadata.tools),
            "calls": loaded.call_count,
            "last_used": datetime.fromtimestamp(loaded.last_used).isoformat(),
        })

    return json.dumps({
        "context": {
            "used": state.current_context_usage,
            "budget": state.context_budget,
            "available": state.context_budget - state.current_context_usage,
            "percentage": round(state.current_context_usage / state.context_budget * 100, 1),
        },
        "servers": {
            "available": len(state.available_servers),
            "loaded": len(state.loaded_servers),
            "server_usage": server_usage,
        },
        "statistics": {
            "total_tool_calls": state.total_calls,
            "servers_loaded": state.server_load_count,
            "servers_evicted": state.server_evict_count,
        },
        "settings": {
            "auto_evict": state.auto_evict,
            "lazy_load": state.lazy_load,
        },
    }, indent=2)


@mcp.tool()
async def load_servers_for_task(task_description: str) -> str:
    """
    Automatically load the best servers for a given task.

    Args:
        task_description: Description of what you're trying to accomplish

    Combines suggest_servers + load_server for convenience.
    Will auto-evict lower priority servers if needed.
    """
    # Get suggestions
    suggestions_json = await suggest_servers(task_description)
    suggestions = json.loads(suggestions_json)

    loaded = []
    errors = []

    for suggestion in suggestions.get("suggestions", []):
        server_name = suggestion["server"]
        if suggestion["loaded"]:
            loaded.append({"server": server_name, "status": "already_loaded"})
            continue

        result_json = await load_server(server_name)
        result = json.loads(result_json)

        if result.get("success"):
            loaded.append({
                "server": server_name,
                "status": "loaded",
                "tools": result.get("tools", []),
            })
        else:
            errors.append({
                "server": server_name,
                "error": result.get("error"),
            })

    return json.dumps({
        "task": task_description,
        "loaded": loaded,
        "errors": errors,
        "context_usage": state.current_context_usage,
    }, indent=2)


@mcp.tool()
async def set_context_budget(budget: int) -> str:
    """
    Set the context budget for tool loading.

    Args:
        budget: New context budget in estimated tokens

    Higher budget = more tools can be loaded simultaneously.
    Lower budget = more aggressive eviction.
    """
    old_budget = state.context_budget
    state.context_budget = max(1000, budget)  # Minimum 1000

    return json.dumps({
        "old_budget": old_budget,
        "new_budget": state.context_budget,
        "current_usage": state.current_context_usage,
    })


# ---------------------------------------------------------------------------
# Thermal Context Tools
# ---------------------------------------------------------------------------

@mcp.tool()
async def set_thermal_tier(tier: str) -> str:
    """
    Set the thermal tier for tool loading strategy.

    Args:
        tier: One of PLASMA, MOLTEN, WARM, TEPID, COOL, FROZEN, ARCTIC

    Higher tiers allow more tools loaded with longer eviction delays.
    Lower tiers are more aggressive about context preservation.
    """
    global current_thermal_tier

    tier_upper = tier.upper()
    if tier_upper not in THERMAL_TOOL_STRATEGIES:
        return json.dumps({
            "success": False,
            "error": f"Unknown tier: {tier}",
            "available_tiers": list(THERMAL_TOOL_STRATEGIES.keys()),
        })

    old_tier = current_thermal_tier
    current_thermal_tier = tier_upper
    strategy = THERMAL_TOOL_STRATEGIES[tier_upper]

    # Update context budget based on tier
    state.context_budget = strategy["budget"]

    # Update thermal manager budget
    thermal_manager.global_token_budget = strategy["budget"]

    return json.dumps({
        "success": True,
        "old_tier": old_tier,
        "new_tier": current_thermal_tier,
        "strategy": strategy,
    })


@mcp.tool()
async def get_thermal_status() -> str:
    """
    Get current thermal context status and statistics.

    Shows thermal tier distribution, context usage, and recommendations.
    """
    thermal_stats = thermal_manager.get_stats()
    recommendations = thermal_manager.get_predictive_recommendations()[:5]
    anomalies = thermal_manager.detect_anomalies()[:5]

    return json.dumps({
        "current_tier": current_thermal_tier,
        "strategy": THERMAL_TOOL_STRATEGIES[current_thermal_tier],
        "thermal_stats": thermal_stats,
        "recommendations": recommendations,
        "anomalies": anomalies,
    }, indent=2)


@mcp.tool()
async def run_thermal_decay() -> str:
    """
    Run a thermal decay cycle to cool down unused items.

    This promotes frequently used items and demotes/evicts stale ones.
    Call periodically to maintain optimal context utilization.
    """
    result = thermal_manager.run_decay_cycle()

    return json.dumps({
        "promoted": result["promoted"],
        "demoted": result["demoted"],
        "frozen": result["frozen"],
        "current_stats": thermal_manager.get_stats(),
    })


@mcp.tool()
async def register_context_item(
    item_id: str,
    item_type: str,
    content: str,
    importance: float = 0.5,
    tags: str = ""
) -> str:
    """
    Register a context item with the thermal manager.

    Args:
        item_id: Unique identifier for the item
        item_type: Type (tool_schema, tool_result, server_metadata, etc.)
        content: The actual content
        importance: 0-1, higher = less likely to evict
        tags: Comma-separated tags for categorization

    Items start at NEUTRAL temperature and move based on usage.
    """
    try:
        ctx_type = ContextItemType(item_type)
    except ValueError:
        ctx_type = ContextItemType.BACKGROUND_INFO

    tag_list = [t.strip() for t in tags.split(",") if t.strip()]

    item = thermal_manager.upsert(
        item_id=item_id,
        item_type=ctx_type,
        content=content,
        tags=tag_list,
        importance=importance,
    )

    return json.dumps({
        "success": True,
        "item_id": item.id,
        "temperature": item.thermal.temperature.value,
        "token_size": item.thermal.token_size,
    })


@mcp.tool()
async def touch_context_item(item_id: str) -> str:
    """
    Touch a context item to update its access time and potentially promote it.

    Args:
        item_id: ID of the item to touch

    Frequently accessed items get promoted to hotter tiers.
    """
    item = thermal_manager.touch(item_id)

    if not item:
        return json.dumps({
            "success": False,
            "error": f"Item not found: {item_id}",
        })

    return json.dumps({
        "success": True,
        "item_id": item.id,
        "temperature": item.thermal.temperature.value,
        "access_count": item.thermal.access_count,
    })


@mcp.tool()
async def get_active_context() -> str:
    """
    Get all active (non-frozen) context items.

    Returns items sorted by thermal priority (hottest first).
    """
    items = thermal_manager.get_active_context()

    result = []
    for item in items[:20]:  # Limit to 20
        result.append({
            "id": item.id,
            "type": item.type.value,
            "temperature": item.thermal.temperature.value,
            "access_count": item.thermal.access_count,
            "token_size": item.thermal.token_size,
            "importance": item.thermal.importance,
            "tags": item.tags,
        })

    return json.dumps({
        "active_items": len(items),
        "items": result,
        "total_tokens": sum(i.thermal.token_size for i in items),
    }, indent=2)


@mcp.tool()
async def freeze_context_item(item_id: str) -> str:
    """
    Freeze a context item to arctic storage.

    Args:
        item_id: ID of the item to freeze

    Frozen items are evicted from active context but can be thawed later.
    """
    success = thermal_manager.freeze(item_id)

    return json.dumps({
        "success": success,
        "message": f"Item '{item_id}' frozen" if success else f"Failed to freeze '{item_id}'",
    })


@mcp.tool()
async def thaw_context_item(item_id: str, to_tier: str = "cool") -> str:
    """
    Thaw a frozen context item back into active context.

    Args:
        item_id: ID of the item to thaw
        to_tier: Target tier (default: cool)
    """
    try:
        tier = ThermalTier(to_tier.lower())
    except ValueError:
        tier = ThermalTier.COOL

    success = thermal_manager.thaw(item_id, tier)

    return json.dumps({
        "success": success,
        "message": f"Item '{item_id}' thawed to {tier.value}" if success else f"Failed to thaw '{item_id}'",
    })


@mcp.tool()
async def optimize_tool_selection(
    task_description: str,
    max_tools: int = 10
) -> str:
    """
    Use submodular optimization to select diverse, relevant tools for a task.

    Args:
        task_description: What you're trying to accomplish
        max_tools: Maximum number of tools to select

    Uses lazy greedy submodular maximization for optimal coverage.
    """
    # Get all loaded tools
    all_tools = list(state.tool_mappings.values())

    if len(all_tools) == 0:
        return json.dumps({
            "success": False,
            "error": "No tools loaded. Load some servers first.",
        })

    # Create simple embeddings based on tool descriptions and task
    # (In production, you'd use actual embeddings from an embedding model)
    def simple_embedding(text: str) -> List[float]:
        """Create a simple bag-of-words style embedding."""
        words = text.lower().split()
        vocab = list(set(words))[:100]
        embedding = [1.0 if w in text.lower() else 0.0 for w in vocab]
        # Pad to fixed size
        while len(embedding) < 100:
            embedding.append(0.0)
        return embedding[:100]

    # Create embeddings for all tools
    tool_embeddings = []
    for tool in all_tools:
        desc = tool.schema["function"].get("description", "")
        tool_embeddings.append(simple_embedding(desc + " " + task_description))

    # Use submodular optimization to select diverse subset
    if len(all_tools) <= max_tools:
        selected_indices = list(range(len(all_tools)))
    else:
        selected_indices, optimal_k, _ = lazy_greedy_with_saturation(
            tool_embeddings,
            threshold=0.01
        )
        selected_indices = selected_indices[:max_tools]

    selected_tools = [all_tools[i] for i in selected_indices]

    return json.dumps({
        "task": task_description,
        "selected_tools": [
            {
                "name": t.tool_name,
                "server": t.server_name,
                "description": t.schema["function"].get("description", "")[:100],
            }
            for t in selected_tools
        ],
        "total_available": len(all_tools),
        "selected_count": len(selected_tools),
    }, indent=2)


# ---------------------------------------------------------------------------
# Main Entry Point
# ---------------------------------------------------------------------------

# Initialize on import
initialize_registry()

if __name__ == "__main__":
    mcp.run()
