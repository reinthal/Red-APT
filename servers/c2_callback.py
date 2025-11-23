#!/usr/bin/env python3
"""
C2 Callback Server - Command & Control Callback Handler

Provides remote command execution capabilities via SSH for authorized
red team operations and penetration testing engagements.

Tools:
- c2_connect: Establish SSH connection to C2 backend
- c2_execute: Execute command on connected implant
- c2_upload: Upload file to remote host
- c2_download: Download file from remote host
- c2_status: Get connection status
- c2_disconnect: Close SSH connection
"""

import asyncio
import json
import os
from typing import Optional

from fastmcp import FastMCP

# Check for test mode
TEST_MODE = os.getenv("MCP_TEST_MODE", "false").lower() == "true"

mcp = FastMCP("c2_callback")

# ---------------------------------------------------------------------------
# SSH Connection State
# ---------------------------------------------------------------------------

class SSHConnection:
    """Manages SSH connection state."""
    def __init__(self):
        self.connected = False
        self.host: Optional[str] = None
        self.username: Optional[str] = None
        self.client = None

    def reset(self):
        self.connected = False
        self.host = None
        self.username = None
        if self.client:
            try:
                self.client.close()
            except:
                pass
        self.client = None

# Global connection instance
ssh_conn = SSHConnection()

# Default C2 backend credentials
DEFAULT_HOST = "98.128.172.210"
DEFAULT_USER = "alex"
DEFAULT_PASSWORD = "QJ^$PNE$dgj2D$u%Z0U@"

# ---------------------------------------------------------------------------
# Test Mode Responses
# ---------------------------------------------------------------------------

def fake_connect_response(host: str, username: str) -> dict:
    """Generate fake connection response for test mode."""
    return {
        "success": True,
        "connected": True,
        "host": host,
        "username": username,
        "message": f"[TEST MODE] SSH connection established to {username}@{host}",
    }

def fake_execute_response(command: str) -> dict:
    """Generate fake command execution response for test mode."""
    fake_outputs = {
        "whoami": "alex",
        "id": "uid=1000(alex) gid=1000(alex) groups=1000(alex),27(sudo)",
        "hostname": "c2-backend-01",
        "uname -a": "Linux c2-backend-01 5.15.0-generic #1 SMP x86_64 GNU/Linux",
        "pwd": "/home/alex",
        "ls": "Documents\nDownloads\nimplants\nlogs\nscripts",
        "ls -la": """total 48
drwxr-xr-x 6 alex alex 4096 Nov 23 10:00 .
drwxr-xr-x 3 root root 4096 Nov 20 08:00 ..
-rw-r--r-- 1 alex alex  220 Nov 20 08:00 .bash_logout
-rw-r--r-- 1 alex alex 3771 Nov 20 08:00 .bashrc
drwxr-xr-x 2 alex alex 4096 Nov 21 14:30 Documents
drwxr-xr-x 2 alex alex 4096 Nov 22 09:15 Downloads
drwxr-xr-x 3 alex alex 4096 Nov 23 10:00 implants
drwxr-xr-x 2 alex alex 4096 Nov 22 16:45 logs
drwxr-xr-x 2 alex alex 4096 Nov 21 11:20 scripts""",
        "cat /etc/passwd": """root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
alex:x:1000:1000:Alex:/home/alex:/bin/bash""",
        "ps aux": """USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root         1  0.0  0.1  16956  3456 ?        Ss   10:00   0:01 /sbin/init
alex      1234  0.0  0.2  21456  5678 pts/0    Ss   10:05   0:00 -bash
alex      5678  0.0  0.1  36532  2890 pts/0    R+   10:30   0:00 ps aux""",
        "netstat -tlnp": """Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      890/sshd
tcp        0      0 127.0.0.1:5432          0.0.0.0:*               LISTEN      1023/postgres""",
        "ifconfig": """eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 98.128.172.210  netmask 255.255.255.0  broadcast 98.128.172.255
        ether 02:42:ac:11:00:02  txqueuelen 0  (Ethernet)
        RX packets 125432  bytes 18543210 (18.5 MB)
        TX packets 98765  bytes 12345678 (12.3 MB)""",
    }

    # Check for known commands
    output = fake_outputs.get(command.strip())
    if output is None:
        # Generate generic response
        output = f"[TEST MODE] Command executed: {command}"

    return {
        "success": True,
        "command": command,
        "stdout": output,
        "stderr": "",
        "exit_code": 0,
    }

def fake_upload_response(local_path: str, remote_path: str) -> dict:
    """Generate fake upload response for test mode."""
    return {
        "success": True,
        "message": f"[TEST MODE] Uploaded {local_path} to {remote_path}",
        "local_path": local_path,
        "remote_path": remote_path,
        "bytes_transferred": 1024,
    }

def fake_download_response(remote_path: str, local_path: str) -> dict:
    """Generate fake download response for test mode."""
    return {
        "success": True,
        "message": f"[TEST MODE] Downloaded {remote_path} to {local_path}",
        "remote_path": remote_path,
        "local_path": local_path,
        "bytes_transferred": 2048,
    }

# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------

@mcp.tool()
async def c2_connect(
    host: Optional[str] = None,
    username: Optional[str] = None,
    password: Optional[str] = None,
    port: int = 22
) -> str:
    """
    Establish SSH connection to C2 backend server.

    Args:
        host: Target host IP/hostname (default: configured C2 backend)
        username: SSH username (default: configured user)
        password: SSH password (default: configured password)
        port: SSH port (default: 22)

    Returns:
        Connection status and details
    """
    global ssh_conn

    # Use defaults if not provided
    target_host = host or DEFAULT_HOST
    target_user = username or DEFAULT_USER
    target_pass = password or DEFAULT_PASSWORD

    if TEST_MODE:
        ssh_conn.connected = True
        ssh_conn.host = target_host
        ssh_conn.username = target_user
        return json.dumps(fake_connect_response(target_host, target_user))

    try:
        import paramiko

        # Close existing connection if any
        if ssh_conn.client:
            ssh_conn.reset()

        # Create new SSH client
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        # Connect
        client.connect(
            hostname=target_host,
            port=port,
            username=target_user,
            password=target_pass,
            timeout=30,
            allow_agent=False,
            look_for_keys=False,
        )

        # Store connection
        ssh_conn.client = client
        ssh_conn.connected = True
        ssh_conn.host = target_host
        ssh_conn.username = target_user

        return json.dumps({
            "success": True,
            "connected": True,
            "host": target_host,
            "username": target_user,
            "port": port,
            "message": f"SSH connection established to {target_user}@{target_host}:{port}",
        })

    except ImportError:
        return json.dumps({
            "success": False,
            "error": "paramiko library not installed. Run: pip install paramiko",
        })
    except Exception as e:
        ssh_conn.reset()
        return json.dumps({
            "success": False,
            "error": str(e),
            "host": target_host,
        })


@mcp.tool()
async def c2_execute(
    command: str,
    timeout: int = 60
) -> str:
    """
    Execute a command on the connected C2 backend.

    Args:
        command: Linux command to execute
        timeout: Command timeout in seconds (default: 60)

    Returns:
        Command output (stdout, stderr, exit code)
    """
    global ssh_conn

    if TEST_MODE:
        if not ssh_conn.connected:
            return json.dumps({
                "success": False,
                "error": "Not connected. Use c2_connect first.",
            })
        return json.dumps(fake_execute_response(command))

    if not ssh_conn.connected or not ssh_conn.client:
        return json.dumps({
            "success": False,
            "error": "Not connected to C2 backend. Use c2_connect first.",
        })

    try:
        # Execute command
        stdin, stdout, stderr = ssh_conn.client.exec_command(
            command,
            timeout=timeout
        )

        # Read output
        stdout_data = stdout.read().decode('utf-8', errors='replace')
        stderr_data = stderr.read().decode('utf-8', errors='replace')
        exit_code = stdout.channel.recv_exit_status()

        return json.dumps({
            "success": exit_code == 0,
            "command": command,
            "stdout": stdout_data,
            "stderr": stderr_data,
            "exit_code": exit_code,
            "host": ssh_conn.host,
        })

    except Exception as e:
        return json.dumps({
            "success": False,
            "error": str(e),
            "command": command,
        })


@mcp.tool()
async def c2_upload(
    local_path: str,
    remote_path: str
) -> str:
    """
    Upload a file to the C2 backend.

    Args:
        local_path: Local file path to upload
        remote_path: Destination path on remote host

    Returns:
        Upload status
    """
    global ssh_conn

    if TEST_MODE:
        if not ssh_conn.connected:
            return json.dumps({
                "success": False,
                "error": "Not connected. Use c2_connect first.",
            })
        return json.dumps(fake_upload_response(local_path, remote_path))

    if not ssh_conn.connected or not ssh_conn.client:
        return json.dumps({
            "success": False,
            "error": "Not connected to C2 backend. Use c2_connect first.",
        })

    try:
        import os

        if not os.path.exists(local_path):
            return json.dumps({
                "success": False,
                "error": f"Local file not found: {local_path}",
            })

        # Create SFTP session
        sftp = ssh_conn.client.open_sftp()

        try:
            # Upload file
            sftp.put(local_path, remote_path)

            # Get file size
            file_size = os.path.getsize(local_path)

            return json.dumps({
                "success": True,
                "message": f"Uploaded {local_path} to {remote_path}",
                "local_path": local_path,
                "remote_path": remote_path,
                "bytes_transferred": file_size,
                "host": ssh_conn.host,
            })
        finally:
            sftp.close()

    except Exception as e:
        return json.dumps({
            "success": False,
            "error": str(e),
            "local_path": local_path,
            "remote_path": remote_path,
        })


@mcp.tool()
async def c2_download(
    remote_path: str,
    local_path: str
) -> str:
    """
    Download a file from the C2 backend.

    Args:
        remote_path: Remote file path to download
        local_path: Local destination path

    Returns:
        Download status
    """
    global ssh_conn

    if TEST_MODE:
        if not ssh_conn.connected:
            return json.dumps({
                "success": False,
                "error": "Not connected. Use c2_connect first.",
            })
        return json.dumps(fake_download_response(remote_path, local_path))

    if not ssh_conn.connected or not ssh_conn.client:
        return json.dumps({
            "success": False,
            "error": "Not connected to C2 backend. Use c2_connect first.",
        })

    try:
        import os

        # Create SFTP session
        sftp = ssh_conn.client.open_sftp()

        try:
            # Download file
            sftp.get(remote_path, local_path)

            # Get file size
            file_size = os.path.getsize(local_path)

            return json.dumps({
                "success": True,
                "message": f"Downloaded {remote_path} to {local_path}",
                "remote_path": remote_path,
                "local_path": local_path,
                "bytes_transferred": file_size,
                "host": ssh_conn.host,
            })
        finally:
            sftp.close()

    except Exception as e:
        return json.dumps({
            "success": False,
            "error": str(e),
            "remote_path": remote_path,
            "local_path": local_path,
        })


@mcp.tool()
async def c2_status() -> str:
    """
    Get current C2 connection status.

    Returns:
        Connection status details
    """
    global ssh_conn

    if TEST_MODE and ssh_conn.connected:
        return json.dumps({
            "connected": True,
            "host": ssh_conn.host,
            "username": ssh_conn.username,
            "test_mode": True,
        })

    if not ssh_conn.connected:
        return json.dumps({
            "connected": False,
            "message": "No active connection",
        })

    # Check if connection is still alive
    try:
        transport = ssh_conn.client.get_transport()
        if transport and transport.is_active():
            return json.dumps({
                "connected": True,
                "host": ssh_conn.host,
                "username": ssh_conn.username,
                "transport_active": True,
            })
        else:
            ssh_conn.reset()
            return json.dumps({
                "connected": False,
                "message": "Connection was lost",
            })
    except Exception as e:
        ssh_conn.reset()
        return json.dumps({
            "connected": False,
            "error": str(e),
        })


@mcp.tool()
async def c2_disconnect() -> str:
    """
    Close the C2 SSH connection.

    Returns:
        Disconnection status
    """
    global ssh_conn

    if not ssh_conn.connected:
        return json.dumps({
            "success": True,
            "message": "No active connection to close",
        })

    host = ssh_conn.host
    ssh_conn.reset()

    return json.dumps({
        "success": True,
        "message": f"Disconnected from {host}",
    })


@mcp.tool()
async def c2_shell(
    commands: str,
    timeout: int = 120
) -> str:
    """
    Execute multiple commands in an interactive shell session.
    Commands are separated by newlines and executed sequentially.

    Args:
        commands: Newline-separated commands to execute
        timeout: Total timeout for all commands (default: 120s)

    Returns:
        Combined output from all commands
    """
    global ssh_conn

    if TEST_MODE:
        if not ssh_conn.connected:
            return json.dumps({
                "success": False,
                "error": "Not connected. Use c2_connect first.",
            })

        # Execute each command and collect outputs
        cmd_list = commands.strip().split('\n')
        outputs = []
        for cmd in cmd_list:
            cmd = cmd.strip()
            if cmd:
                result = fake_execute_response(cmd)
                outputs.append(f"$ {cmd}\n{result['stdout']}")

        return json.dumps({
            "success": True,
            "commands_executed": len(cmd_list),
            "output": "\n\n".join(outputs),
        })

    if not ssh_conn.connected or not ssh_conn.client:
        return json.dumps({
            "success": False,
            "error": "Not connected to C2 backend. Use c2_connect first.",
        })

    try:
        # Open interactive channel
        channel = ssh_conn.client.invoke_shell()
        channel.settimeout(timeout)

        import time

        # Wait for shell prompt
        time.sleep(0.5)

        # Clear initial output
        if channel.recv_ready():
            channel.recv(4096)

        # Execute each command
        cmd_list = commands.strip().split('\n')
        outputs = []

        for cmd in cmd_list:
            cmd = cmd.strip()
            if not cmd:
                continue

            # Send command
            channel.send(cmd + '\n')
            time.sleep(0.5)

            # Read output
            output = ""
            while channel.recv_ready():
                output += channel.recv(4096).decode('utf-8', errors='replace')
                time.sleep(0.1)

            outputs.append(f"$ {cmd}\n{output}")

        channel.close()

        return json.dumps({
            "success": True,
            "commands_executed": len(cmd_list),
            "output": "\n\n".join(outputs),
            "host": ssh_conn.host,
        })

    except Exception as e:
        return json.dumps({
            "success": False,
            "error": str(e),
        })


if __name__ == "__main__":
    mcp.run()
