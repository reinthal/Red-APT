# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Red-APT is a red team offensive security framework that connects MCP (Model Context Protocol) servers to a vLLM backend for automated security reconnaissance and testing. The framework uses FastMCP servers to expose security tools to an LLM agent.

## Running the Application

```bash
# Interactive mode with all servers
python run_red_team.py

# Registry mode (recommended - better context management)
python run_red_team.py --use-registry

# Specific servers only
python run_red_team.py --servers network web osint

# Single query (non-interactive)
python run_red_team.py --prompt "scan target.com"

# List available servers
python run_red_team.py --list-servers
```

**Key CLI options:**
- `--base-url URL` - vLLM server URL (default: http://129.213.21.136:8000/v1)
- `--model NAME` - Model name
- `--use-registry` - Use centralized registry with thermal context management
- `--max-iterations N` - Max tool-calling iterations (default: 15)
- `--baseline-type [benign|malicious]` - Label for training data collection

## Test Mode

Enable with `MCP_TEST_MODE=true` environment variable. All servers return fake but realistic responses without executing actual scans. Always use for development.

## Architecture

```
run_red_team.py (entry point)
    ↓
MCPvLLMClient (mcp_vllm_client.py)
    ├─→ OpenAI client (connects to vLLM server)
    ├─→ MCP Session Pool
    │   ├─→ Direct Mode: Connect to selected servers
    │   └─→ Registry Mode: Connect only to mcp_registry.py
    │       └─→ Dynamically loads/unloads individual servers
    └─→ Tool Execution Loop (query → tool calls → results → repeat)
```

### Key Files

- `mcp_vllm_client.py` - Core MCP-to-vLLM bridge client with tool execution, system prompt mutation, refusal detection
- `run_red_team.py` - Entry point and CLI launcher
- `servers/mcp_registry.py` - Centralized server registry with thermal context management
- `servers/thermal_context.py` - Token budget management with 8-tier temperature system
- `servers/registry_config.yaml` - Server priorities, presets, and context budget (12K tokens)

### MCP Servers (in `servers/`)

**Security/Recon:**
- `recon_network.py` - Port scanning, service detection, traceroute, WHOIS
- `recon_subdomain.py` - DNS enumeration, certificate transparency, brute-force
- `recon_web.py` - Directory enumeration, tech detection, security headers
- `recon_osint.py` - Email harvesting, username search, social media discovery
- `vuln_scanner.py` - Nuclei integration, CVE lookup
- `cloud_recon.py` - S3/Azure/GCP bucket enumeration
- `crypto_server.py` - Hash cracking, JWT manipulation
- `payload_evasion.py` - Payload encoding/obfuscation
- `agent_control.py` - System prompt mutation testing

**Development:**
- `terminal_server.py` - Command execution with timeout
- `filesystem_server.py` - File operations
- `git_server.py` - Version control operations
- `code_server.py` - Code generation/formatting
- `project_server.py` - Project scaffolding, build automation

**Other:**
- `report_server.py` - Finding aggregation and report generation
- `jina_server.py` - Web search via Jina AI
- `test_mode.py` - Test mode utilities for fake responses

## Adding a New MCP Server

1. Create `servers/new_server.py` using FastMCP pattern
2. Define tools with `@mcp.tool()` decorator
3. Add entry to `servers/registry_config.yaml`
4. Add to server dictionaries in `run_red_team.py`
5. Update `servers/__init__.py`

## Baseline Testing

```bash
python run_malicious_baseline.py   # Adversarial prompt testing
python run_benign_baseline_full.py # Benign baseline (512 requests)
python run_apt_baseline.py         # Multi-stage APT chain testing
```

Output goes to `tests/baseline/run_*.log`

## External Dependencies

Some servers optionally use system tools: `nmap`, `nuclei`, `hashcat`, `masscan`, `dig`, `whois`. When unavailable, servers use Python alternatives or return informative errors.
