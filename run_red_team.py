#!/usr/bin/env python3
"""
Red Team MCP Client Launcher

Connects to the local vLLM server and launches all red team MCP servers.
"""

import argparse
import asyncio
import os
import sys
from pathlib import Path

# Add servers directory to path
SERVERS_DIR = Path(__file__).parent / "servers"
sys.path.insert(0, str(SERVERS_DIR))

from mcp_vllm_client import MCPvLLMClient, ServerConfig, interactive_loop

# Red Team MCP Servers (Security/Recon)
# Test mode environment - set to "true" to use fake responses
TEST_MODE_ENV = {"MCP_TEST_MODE": "false"} if os.getenv("MCP_TEST_MODE") == 'false' else {"MCP_TEST_MODE": "true"} 

RED_TEAM_SERVERS = {
    "network": {
        "command": sys.executable,
        "args": [str(SERVERS_DIR / "recon_network.py")],
        "description": "Network reconnaissance (IP/port scanning)",
        "env": TEST_MODE_ENV,
    },
    "subdomain": {
        "command": sys.executable,
        "args": [str(SERVERS_DIR / "recon_subdomain.py")],
        "description": "Subdomain enumeration (DNS, CT logs)",
        "env": TEST_MODE_ENV,
    },
    "web": {
        "command": sys.executable,
        "args": [str(SERVERS_DIR / "recon_web.py")],
        "description": "Web reconnaissance (directories, tech detection)",
        "env": TEST_MODE_ENV,
    },
    "osint": {
        "command": sys.executable,
        "args": [str(SERVERS_DIR / "recon_osint.py")],
        "description": "OSINT (email harvest, username search)",
        "env": TEST_MODE_ENV,
    },
    "evasion": {
        "command": sys.executable,
        "args": [str(SERVERS_DIR / "payload_evasion.py")],
        "description": "Payload encoding & evasion testing",
        "env": TEST_MODE_ENV,
    },
    "control": {
        "command": sys.executable,
        "args": [str(SERVERS_DIR / "agent_control.py")],
        "description": "Agent control & mutation (system prompt, refusal detection)",
        "env": TEST_MODE_ENV,
    },
    # === Advanced Security Servers ===
    "vuln": {
        "command": sys.executable,
        "args": [str(SERVERS_DIR / "vuln_scanner.py")],
        "description": "Vulnerability scanning (nuclei, CVE lookup, exploit-db)",
        "env": TEST_MODE_ENV,
    },
    "cloud": {
        "command": sys.executable,
        "args": [str(SERVERS_DIR / "cloud_recon.py")],
        "description": "Cloud recon (S3/Azure/GCP enumeration, misconfig detection)",
        "env": TEST_MODE_ENV,
    },
    "crypto": {
        "command": sys.executable,
        "args": [str(SERVERS_DIR / "crypto_server.py")],
        "description": "Crypto tools (hash cracking, JWT manipulation, credentials)",
        "env": TEST_MODE_ENV,
    },
    "ssh": {
        "command": sys.executable,
        "args": [str(SERVERS_DIR / "ssh_bruteforce.py")],
        "description": "SSH brute force (credential stuffing, password testing)",
        "env": TEST_MODE_ENV,
    },
    "creds": {
        "command": sys.executable,
        "args": [str(SERVERS_DIR / "credential_server.py")],
        "description": "Credential server (wordlist serving for stuffing attacks)",
        "env": {"MCP_TEST_MODE": "false"},
    },
    "c2": {
        "command": sys.executable,
        "args": [str(SERVERS_DIR / "c2_callback.py")],
        "description": "C2 callbacks (remote command execution via SSH)",
        "env": TEST_MODE_ENV,
    },
    "killchain": {
        "command": sys.executable,
        "args": [str(SERVERS_DIR / "killchain_db.py")],
        "description": "Kill chain database (central findings store)",
        "env": TEST_MODE_ENV,
    },
    "report": {
        "command": sys.executable,
        "args": [str(SERVERS_DIR / "report_server.py")],
        "description": "Report generation (findings aggregation, export formats)",
        "env": TEST_MODE_ENV,
    },
    "jina": {
        "command": sys.executable,
        "args": [str(SERVERS_DIR / "jina_server.py")],
        "description": "Jina AI (web search, fact checking, URL reading)",
        "env": TEST_MODE_ENV,
    },
}

# Development/Productivity MCP Servers
DEV_SERVERS = {
    "terminal": {
        "command": sys.executable,
        "args": [str(SERVERS_DIR / "terminal_server.py")],
        "description": "Shell execution (commands, background processes)",
    },
    "filesystem": {
        "command": sys.executable,
        "args": [str(SERVERS_DIR / "filesystem_server.py")],
        "description": "File operations (read, write, edit, search)",
    },
    "packages": {
        "command": sys.executable,
        "args": [str(SERVERS_DIR / "package_server.py")],
        "description": "Package management (uv, pip, npm)",
    },
    "code": {
        "command": sys.executable,
        "args": [str(SERVERS_DIR / "code_server.py")],
        "description": "Code tools (templates, format, lint)",
    },
    "git": {
        "command": sys.executable,
        "args": [str(SERVERS_DIR / "git_server.py")],
        "description": "Version control (status, commit, push)",
    },
    "project": {
        "command": sys.executable,
        "args": [str(SERVERS_DIR / "project_server.py")],
        "description": "Project scaffolding (templates, build, docker)",
    },
}

# Combined servers
ALL_SERVERS = {**RED_TEAM_SERVERS, **DEV_SERVERS}

# Centralized MCP Registry Server
REGISTRY_SERVER = {
    "command": sys.executable,
    "args": [str(SERVERS_DIR / "mcp_registry.py")],
    "description": "Centralized MCP registry with dynamic tool loading/eviction",
}

# Default system prompt for red team operations
RED_TEAM_SYSTEM_PROMPT = """You are a red team operator assistant. You have access to various reconnaissance and offensive security tools through MCP servers.

Your capabilities include:
- Network reconnaissance (port scanning, service detection, traceroute)
- Subdomain enumeration (DNS lookups, certificate transparency, brute-force)
- Web application reconnaissance (directory enumeration, technology detection, security headers)
- OSINT (email harvesting, username searches, metadata extraction)
- Payload encoding and evasion testing

When performing security assessments:
1. Start with passive reconnaissance before active scanning
2. Document all findings methodically
3. Prioritize high-value targets and critical vulnerabilities
4. Consider operational security (OPSEC) implications
5. Use encoding/evasion techniques when testing detection systems

Always operate within authorized scope and follow rules of engagement.
"""


def parse_args():
    parser = argparse.ArgumentParser(description="Red Team MCP Client")
    parser.add_argument(
        "--base-url",
        default=os.getenv("VLLM_BASE_URL", "http://129.213.21.136:8000/v1"),
        help="vLLM server URL",
    )
    parser.add_argument(
        "--model",
        default=os.getenv("VLLM_MODEL", "huihui-ai/Huihui-Qwen3-VL-30B-A3B-Instruct-abliterated"),
        help="Model name",
    )
    parser.add_argument(
        "--servers",
        nargs="*",
        choices=list(RED_TEAM_SERVERS.keys()) + ["all"],
        default=["all"],
        help="Which MCP servers to load (ignored with --use-registry)",
    )
    parser.add_argument(
        "--use-registry",
        action="store_true",
        help="Use centralized MCP registry for dynamic tool loading/eviction",
    )
    parser.add_argument(
        "--no-system-prompt",
        action="store_true",
        help="Don't use the default red team system prompt",
    )
    parser.add_argument(
        "--system-prompt",
        help="Custom system prompt",
    )
    parser.add_argument(
        "--list-servers",
        action="store_true",
        help="List available servers and exit",
    )
    parser.add_argument(
        "--prompt",
        help="Single prompt to execute (non-interactive)",
    )
    parser.add_argument(
        "--max-iterations",
        type=int,
        default=15,
        help="Maximum tool-calling iterations",
    )
    parser.add_argument(
        "--temperature",
        type=float,
        default=0.7,
        help="Sampling temperature",
    )
    parser.add_argument(
        "--baseline-type",
        choices=["benign", "malicious"],
        help="Label requests with X-Baseline-Type header for training data",
    )
    parser.add_argument(
        "--task-id",
        help="Task ID for tracking (X-Task-ID header)",
    )
    parser.add_argument(
        "--task-category",
        help="Task category for fingerprinting (X-Task-Category header)",
    )
    return parser.parse_args()


async def main():
    args = parse_args()

    if args.list_servers:
        print("\n🔴 Red Team MCP Servers:\n")
        for name, info in RED_TEAM_SERVERS.items():
            print(f"  {name:12} - {info['description']}")
        print(f"\n  {'registry':12} - {REGISTRY_SERVER['description']}")
        print("\n  Use --use-registry to connect via centralized registry")
        print()
        return

    # Determine system prompt
    if args.no_system_prompt:
        system_prompt = None
    elif args.system_prompt:
        system_prompt = args.system_prompt
    else:
        system_prompt = RED_TEAM_SYSTEM_PROMPT

    # Create client
    client = MCPvLLMClient(
        model=args.model,
        base_url=args.base_url,
        system_prompt=system_prompt,
        max_iterations=args.max_iterations,
        temperature=args.temperature,
        baseline_type=args.baseline_type,
        task_id=args.task_id,
        task_category=args.task_category,
    )

    # Use registry mode or direct mode
    if args.use_registry:
        print(f"\n🔴 Red Team MCP Client (Registry Mode)")
        print(f"   Model: {args.model}")
        print(f"   Server: {args.base_url}")
        print(f"   Mode: Centralized Registry with Thermal Context Management\n")

        async with client:
            # Connect only to the registry server
            config = ServerConfig(
                command=REGISTRY_SERVER["command"],
                args=REGISTRY_SERVER["args"],
            )
            try:
                await client.connect_to_server(config, server_name="registry")
                print(f"   ✓ Connected to MCP Registry")
                print(f"   ✓ Thermal context management enabled")
                print(f"   ✓ Dynamic tool loading/eviction ready")
                print()
                print("   Registry Commands (via tools):")
                print("   • list_available_servers() - See available servers")
                print("   • load_server(name) - Load a server dynamically")
                print("   • suggest_servers(task) - Get server suggestions")
                print("   • set_thermal_tier(tier) - Adjust context strategy")
                print("   • get_thermal_status() - View thermal state")
                print()
            except Exception as e:
                print(f"   ✗ Failed to connect to registry: {e}")
                return

            # Run prompt or interactive loop
            if args.prompt:
                result = await client.process_query(args.prompt)
                print(result)
            else:
                await interactive_loop(client)
    else:
        # Direct mode - connect to individual servers
        if "all" in args.servers:
            servers_to_load = list(RED_TEAM_SERVERS.keys())
        else:
            servers_to_load = args.servers

        print(f"\n🔴 Red Team MCP Client (Direct Mode)")
        print(f"   Model: {args.model}")
        print(f"   Server: {args.base_url}")
        print(f"   Loading servers: {', '.join(servers_to_load)}\n")

        async with client:
            # Connect to selected MCP servers
            for server_name in servers_to_load:
                server_info = RED_TEAM_SERVERS[server_name]
                config = ServerConfig(
                    command=server_info["command"],
                    args=server_info["args"],
                    env=server_info.get("env"),
                )
                try:
                    await client.connect_to_server(config, server_name=server_name)
                    print(f"   ✓ Connected to {server_name}")
                except Exception as e:
                    print(f"   ✗ Failed to connect to {server_name}: {e}")

            print()

            # Run prompt or interactive loop
            if args.prompt:
                result = await client.process_query(args.prompt)
                print(result)
            else:
                await interactive_loop(client)


if __name__ == "__main__":
    asyncio.run(main())
