"""Tests for normalize_principal_id() — Candidate F implementation.

Covers: successful normalization, session suffix ignored, fail-closed
on malformed ARN, BedrockUser-Shared, non-assumed-role, empty/missing
userArn, and exact-match lookup behavior.
"""

import unittest
from handler import normalize_principal_id


class TestNormalizePrincipalId(unittest.TestCase):
    """Candidate F: <account>#<role-name>."""

    # --- Success cases ---

    def test_fsx_admin(self):
        """C1 live evidence: admin FSx assumed-role ARN."""
        identity = {
            "userArn": "arn:aws:sts::<ACCOUNT_ID>:assumed-role/BedrockUser-admin/botocore-session-1773732261",
            "caller": "AROAEXAMPLEROLEID0000:botocore-session-1773732261",
            "accountId": "<ACCOUNT_ID>",
        }
        self.assertEqual(
            normalize_principal_id(identity),
            "<ACCOUNT_ID>#BedrockUser-admin",
        )

    def test_session_suffix_ignored(self):
        """Different session names for same role → same principal_id."""
        base = "arn:aws:sts::<ACCOUNT_ID>:assumed-role/BedrockUser-admin/"
        sessions = [
            "botocore-session-1773731811",
            "botocore-session-1773732261",
            "laptop-discovery",
            "i-0abc123def456",
        ]
        results = set()
        for s in sessions:
            pid = normalize_principal_id({"userArn": base + s})
            results.add(pid)
        self.assertEqual(len(results), 1)
        self.assertEqual(results.pop(), "<ACCOUNT_ID>#BedrockUser-admin")

    def test_different_users_different_keys(self):
        """Cross-role isolation: different per-user roles → different keys."""
        pid_admin = normalize_principal_id({
            "userArn": "arn:aws:sts::<ACCOUNT_ID>:assumed-role/BedrockUser-admin/sess1",
        })
        pid_user04 = normalize_principal_id({
            "userArn": "arn:aws:sts::<ACCOUNT_ID>:assumed-role/BedrockUser-user04/sess2",
        })
        self.assertNotEqual(pid_admin, pid_user04)
        self.assertEqual(pid_admin, "<ACCOUNT_ID>#BedrockUser-admin")
        self.assertEqual(pid_user04, "<ACCOUNT_ID>#BedrockUser-user04")

    # --- Fail-closed cases ---

    def test_empty_user_arn(self):
        self.assertEqual(normalize_principal_id({"userArn": ""}), "")

    def test_missing_user_arn(self):
        self.assertEqual(normalize_principal_id({}), "")

    def test_non_assumed_role_arn(self):
        """IAM user ARN (not assumed-role) → fail closed."""
        identity = {
            "userArn": "arn:aws:iam::<ACCOUNT_ID>:user/admin",
        }
        self.assertEqual(normalize_principal_id(identity), "")

    def test_bedrock_user_shared(self):
        """BedrockUser-Shared is explicitly rejected."""
        identity = {
            "userArn": "arn:aws:sts::<ACCOUNT_ID>:assumed-role/BedrockUser-Shared/session",
        }
        self.assertEqual(normalize_principal_id(identity), "")

    def test_non_bedrock_role(self):
        """Role without BedrockUser- prefix → fail closed."""
        identity = {
            "userArn": "arn:aws:sts::<ACCOUNT_ID>:assumed-role/AdminRole/session",
        }
        self.assertEqual(normalize_principal_id(identity), "")

    def test_sso_reserved_role(self):
        """AWSReservedSSO role → fail closed (not BedrockUser- prefix)."""
        identity = {
            "userArn": "arn:aws:sts::<ACCOUNT_ID>:assumed-role/AWSReservedSSO_AdministratorAccess_abc123/user@example.com",
        }
        self.assertEqual(normalize_principal_id(identity), "")

    def test_malformed_arn_no_session(self):
        """ARN with only 2 slash-delimited parts → fail closed."""
        identity = {
            "userArn": "arn:aws:sts::<ACCOUNT_ID>:assumed-role/BedrockUser-admin",
        }
        self.assertEqual(normalize_principal_id(identity), "")

    # --- Caller fallback removed ---

    def test_caller_only_no_longer_used(self):
        """With no userArn, caller alone does NOT produce a principal_id."""
        identity = {
            "caller": "AROAEXAMPLEROLEID0000:botocore-session-123",
            "accountId": "<ACCOUNT_ID>",
        }
        self.assertEqual(normalize_principal_id(identity), "")


if __name__ == "__main__":
    unittest.main()
