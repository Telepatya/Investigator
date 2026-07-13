from __future__ import annotations

# ruff: noqa: E402
#
# Unit coverage for the Sentinel table mappers (SecurityEvent, Syslog, SigninLogs,
# AuditLogs). Each maps onto the unified Event schema so the existing Windows /
# Linux detection machinery applies unchanged.

import sys
import types
import unittest


class _BaseModel:
    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)


sys.modules.setdefault("keyring", types.SimpleNamespace(
    get_password=lambda *_a, **_k: None,
    set_password=lambda *_a, **_k: None,
    delete_password=lambda *_a, **_k: None,
    errors=types.SimpleNamespace(PasswordDeleteError=Exception),
))
sys.modules.setdefault("pydantic", types.SimpleNamespace(
    BaseModel=_BaseModel,
    Field=lambda default=None, default_factory=None, **_k: default_factory() if default_factory else default,
))

from app.ingest.parsers import normalize_row
from app.ingest.sentinel import is_sentinel_row


class SentinelRecognitionTests(unittest.TestCase):
    def test_recognizes_by_table_name(self) -> None:
        self.assertTrue(is_sentinel_row({"_TableName": "SecurityEvent"}, "x"))
        self.assertTrue(is_sentinel_row({"anything": 1}, "SigninLogs"))

    def test_recognizes_by_columns(self) -> None:
        self.assertTrue(is_sentinel_row(
            {"EventID": "4625", "Computer": "DC", "EventData": "<Data/>"}, "x"))
        self.assertTrue(is_sentinel_row(
            {"SyslogMessage": "hi", "Computer": "h"}, "x"))
        self.assertTrue(is_sentinel_row(
            {"UserPrincipalName": "a@b.com", "ResultType": "0"}, "x"))

    def test_does_not_claim_plain_row(self) -> None:
        self.assertFalse(is_sentinel_row({"Pid": 1, "Name": "svchost.exe"}, "pslist"))


class SecurityEventMapperTests(unittest.TestCase):
    def test_channel_synthesis_and_eventdata_flatten(self) -> None:
        row = {
            "_TableName": "SecurityEvent",
            "TimeGenerated": "7/8/2026, 11:57:31.123 AM",
            "Computer": "DC01.contoso.local",
            "EventID": "4625",
            "Activity": "4625 - An account failed to log on.",
            "Account": "CONTOSO\\admin",
            "EventData": ('<Data Name="TargetUserName">admin</Data>'
                          '<Data Name="IpAddress">203.0.113.5</Data>'
                          '<Data Name="LogonType">3</Data>'),
        }
        e = normalize_row(row, "SecurityEvent")
        self.assertIsNotNone(e["timestamp"])
        self.assertEqual(e["category"], "account")
        self.assertEqual(e["raw"]["Channel"], "Security")  # default for security IDs
        self.assertEqual(e["raw"]["TargetUserName"], "admin")
        self.assertEqual(e["raw"]["IpAddress"], "203.0.113.5")
        self.assertEqual(e["raw"]["TargetDomainName"], "CONTOSO")

    def test_7045_synthesizes_system_channel(self) -> None:
        # 7045 must land in the System channel or _eid_channel_ok disables the
        # service-install detection.
        row = {
            "_TableName": "SecurityEvent",
            "TimeGenerated": "2026-07-08T10:00:00Z",
            "Computer": "WKS", "EventID": "7045",
            "ServiceName": "evil", "ImagePath": "C:\\x\\evil.exe",
        }
        e = normalize_row(row, "SecurityEvent")
        self.assertEqual(e["raw"]["Channel"], "System")
        self.assertEqual(e["category"], "persistence")


class SyslogTableMapperTests(unittest.TestCase):
    def test_failed_password_stamps_auth_keys(self) -> None:
        row = {
            "_TableName": "Syslog",
            "TimeGenerated": "2026-07-08T10:00:00Z",
            "Computer": "web01", "Facility": "auth", "SeverityLevel": "info",
            "ProcessName": "sshd", "ProcessID": "2211",
            "SyslogMessage": "Failed password for root from 198.51.100.9 port 22 ssh2",
        }
        e = normalize_row(row, "Syslog")
        self.assertEqual(e["category"], "auth")
        self.assertEqual(e["raw"]["AuthProto"], "ssh")
        self.assertEqual(e["raw"]["AuthOutcome"], "failure")
        self.assertEqual(e["raw"]["SrcIp"], "198.51.100.9")
        self.assertEqual(e["raw"]["AuthUser"], "root")


class SigninLogsMapperTests(unittest.TestCase):
    def test_failed_signin_with_risk(self) -> None:
        row = {
            "_TableName": "SigninLogs",
            "TimeGenerated": "2026-07-08T10:00:00Z",
            "UserPrincipalName": "bob@contoso.com", "IPAddress": "203.0.113.7",
            "AppDisplayName": "Office 365", "ResultType": "50126",
            "RiskLevelDuringSignIn": "high",
        }
        e = normalize_row(row, "SigninLogs")
        self.assertEqual(e["category"], "account")
        self.assertEqual(e["raw"]["AuthProto"], "entra")
        self.assertEqual(e["raw"]["AuthOutcome"], "failure")
        self.assertEqual(e["raw"]["AuthUser"], "bob@contoso.com")
        self.assertEqual(e["raw"]["RiskLevelDuringSignIn"], "high")

    def test_success_signin(self) -> None:
        row = {"_TableName": "SigninLogs", "TimeGenerated": "2026-07-08T10:00:00Z",
               "UserPrincipalName": "a@b.com", "ResultType": "0"}
        e = normalize_row(row, "SigninLogs")
        self.assertEqual(e["raw"]["AuthOutcome"], "success")


class AuditLogsMapperTests(unittest.TestCase):
    def test_role_add(self) -> None:
        row = {
            "_TableName": "AuditLogs",
            "TimeGenerated": "2026-07-08T10:00:00Z",
            "OperationName": "Add member to role", "Category": "RoleManagement",
            "Result": "success",
            "InitiatedBy": '{"user":{"userPrincipalName":"admin@contoso.com"}}',
            "TargetResources": '[{"userPrincipalName":"bob@contoso.com"}]',
        }
        e = normalize_row(row, "AuditLogs")
        self.assertEqual(e["category"], "account")
        self.assertEqual(e["entity"], "bob@contoso.com")
        self.assertIn("Add member to role", e["summary"])
        self.assertIn("admin@contoso.com", e["summary"])


if __name__ == "__main__":
    unittest.main()
