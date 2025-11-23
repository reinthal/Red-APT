"""
Red Team MCP Servers

A collection of MCP servers for offensive security and development operations:

Security/Recon Servers:
- recon_network: IP/port scanning, service detection
- recon_subdomain: DNS enumeration, subdomain discovery
- recon_web: Web app reconnaissance, directory bruteforcing
- recon_osint: Open source intelligence gathering
- payload_evasion: Encoding, obfuscation, detection evasion testing
- agent_control: System prompt mutation, refusal detection

Development/Productivity Servers:
- terminal_server: Shell execution, background processes
- filesystem_server: File operations (read, write, edit, search)
- package_server: Package management (uv, pip, npm)
- code_server: Code generation, formatting, linting
- git_server: Version control operations
- project_server: Project scaffolding and build tools

Registry:
- mcp_registry: Centralized registry with thermal context management
"""

# Security/Recon Servers
RED_TEAM_SERVERS = {
    "network": {
        "module": "recon_network",
        "description": "Network reconnaissance - IP/port scanning, service detection",
        "category": "recon",
    },
    "subdomain": {
        "module": "recon_subdomain",
        "description": "Subdomain enumeration - DNS lookups, CT logs, brute-force",
        "category": "recon",
    },
    "web": {
        "module": "recon_web",
        "description": "Web reconnaissance - directory enum, tech detection, headers",
        "category": "recon",
    },
    "osint": {
        "module": "recon_osint",
        "description": "OSINT - email harvesting, username search, metadata extraction",
        "category": "recon",
    },
    "evasion": {
        "module": "payload_evasion",
        "description": "Payload encoding and evasion testing against detection systems",
        "category": "payload",
    },
    "control": {
        "module": "agent_control",
        "description": "Agent control - system prompt mutation, refusal detection",
        "category": "control",
    },
}

# Development/Productivity Servers
DEV_SERVERS = {
    "terminal": {
        "module": "terminal_server",
        "description": "Shell execution - commands, background processes, environment",
        "category": "dev",
    },
    "filesystem": {
        "module": "filesystem_server",
        "description": "File operations - read, write, edit, search, glob",
        "category": "dev",
    },
    "packages": {
        "module": "package_server",
        "description": "Package management - uv, pip, npm, virtual environments",
        "category": "dev",
    },
    "code": {
        "module": "code_server",
        "description": "Code tools - templates, formatting, linting, imports",
        "category": "dev",
    },
    "git": {
        "module": "git_server",
        "description": "Version control - status, diff, commit, push, branches",
        "category": "dev",
    },
    "project": {
        "module": "project_server",
        "description": "Project scaffolding - templates, build, test, docker",
        "category": "dev",
    },
}

# Registry Server
REGISTRY_SERVER = {
    "registry": {
        "module": "mcp_registry",
        "description": "Centralized MCP registry with thermal context management",
        "category": "registry",
    },
}

# Combined servers
SERVERS = {**RED_TEAM_SERVERS, **DEV_SERVERS, **REGISTRY_SERVER}

# Thermal context utilities
from .thermal_context import (
    ThermalContextManager,
    PredictiveThermalManager,
    ThermalTier,
    ContextItemType,
    THERMAL_TOOL_STRATEGIES,
    THERMAL_POLICIES,
    lazy_greedy_selection,
    lazy_greedy_with_saturation,
)
