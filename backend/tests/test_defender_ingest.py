from __future__ import annotations

# ruff: noqa: E402
#
# Microsoft Defender / M365 Advanced Hunting (Device* tables) ingestion: each
# exported table row is normalized onto the unified Event schema, setting the
# same raw keys the detection engine already consumes for Velociraptor/Sysmon
# data, so the existing correlation/timeline machinery works over Defender data.

import sys
import types
import unittest
from datetime import timezone


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

from app.ingest.parsers import _is_defender_row, normalize_row


class DefenderRecognitionTests(unittest.TestCase):
    def test_recognizes_by_columns(self) -> None:
        row = {"DeviceName": "WKS-01", "ActionType": "ProcessCreated", "FileName": "a.exe"}
        self.assertTrue(_is_defender_row(row, "export"))

    def test_recognizes_by_source_name(self) -> None:
        self.assertTrue(_is_defender_row({"anything": 1}, "DeviceFileEvents"))

    def test_does_not_misclassify_velociraptor_row(self) -> None:
        # A generic Velociraptor pslist row has no DeviceName/ActionType/InitiatingProcess*.
        row = {"Pid": 1234, "Name": "svchost.exe", "Exe": "C:\\Windows\\svchost.exe"}
        self.assertFalse(_is_defender_row(row, "Windows.System.Pslist"))


class DefenderMappingTests(unittest.TestCase):
    def test_process_event(self) -> None:
        row = {
            "Timestamp": "2026-07-06T10:00:00.1234567Z",
            "DeviceName": "WKS-01", "DeviceId": "d-1",
            "ActionType": "ProcessCreated",
            "FileName": "payload.exe",
            "FolderPath": "C:\\Users\\v\\Downloads\\payload.exe",
            "ProcessId": 4242, "ProcessCommandLine": "payload.exe -run",
            "InitiatingProcessFileName": "explorer.exe",
        }
        ev = normalize_row(row, "DeviceProcessEvents")
        self.assertEqual(ev["category"], "process")
        self.assertEqual(ev["entity"], "payload.exe")
        self.assertEqual(ev["host"], "WKS-01")
        self.assertIsNotNone(ev["timestamp"])
        # 7-digit fractional + Z is parsed to a tz-aware UTC datetime
        self.assertEqual(ev["timestamp"].tzinfo, timezone.utc)
        self.assertEqual(ev["raw"]["_defender_table"], "deviceprocessevents")
        self.assertIn("payload.exe -run", ev["summary"])
        self.assertIn("parent: explorer.exe", ev["summary"])

    def test_network_event_sets_engine_keys(self) -> None:
        row = {
            "Timestamp": "2026-07-06T10:03:00Z", "DeviceName": "WKS-01",
            "ActionType": "ConnectionSuccess",
            "RemoteIP": "203.0.113.5", "RemotePort": 443, "Protocol": "Tcp",
            "LocalIP": "10.0.0.9", "LocalPort": 51000,
            "RemoteUrl": "evil-c2.example",
            "InitiatingProcessFileName": "payload.exe",
        }
        ev = normalize_row(row, "DeviceNetworkEvents")
        self.assertEqual(ev["category"], "network")
        self.assertEqual(ev["raw"]["Raddr"], "203.0.113.5")
        self.assertEqual(ev["raw"]["Rport"], "443")
        self.assertEqual(ev["raw"]["Laddr"], "10.0.0.9")
        self.assertEqual(ev["raw"]["Proto"], "Tcp")
        self.assertEqual(ev["raw"]["Url"], "evil-c2.example")
        self.assertEqual(ev["entity"], "payload.exe")

    def test_file_download_sets_url_and_usn_keys(self) -> None:
        row = {
            "Timestamp": "2026-07-06T10:00:00Z", "DeviceName": "WKS-01",
            "ActionType": "FileCreated",
            "FileName": "payload.exe",
            "FolderPath": "C:\\Users\\v\\Downloads\\payload.exe",
            "SHA256": "abc123",
            "FileOriginUrl": "https://evil.example/payload.exe",
            "FileOriginReferrerUrl": "https://evil.example/",
            "InitiatingProcessFileName": "chrome.exe",
        }
        ev = normalize_row(row, "DeviceFileEvents")
        self.assertEqual(ev["category"], "filesystem")
        raw = ev["raw"]
        # download provenance keys the engine already reads
        self.assertEqual(raw["Url"], "https://evil.example/payload.exe")
        self.assertEqual(raw["ReferrerUrl"], "https://evil.example/")
        self.assertEqual(raw["FullPath"], "C:\\Users\\v\\Downloads\\payload.exe")
        # synthetic USN lifecycle keys mirroring the USN-journal normalizer
        self.assertTrue(raw["usn_journal"])
        self.assertEqual(raw["UsnReasonTokens"], ["FILE_CREATE"])
        self.assertEqual(raw["UsnPath"], "C:\\Users\\v\\Downloads\\payload.exe")
        self.assertEqual(raw["UsnFileReference"], "abc123")

    def test_file_rename_carries_previous_path(self) -> None:
        row = {
            "Timestamp": "2026-07-06T10:01:00Z", "DeviceName": "WKS-01",
            "ActionType": "FileRenamed",
            "FileName": "svc.exe", "FolderPath": "C:\\Users\\v\\svc.exe",
            "PreviousFileName": "invoice.pdf.exe",
            "PreviousFolderPath": "C:\\Users\\v\\Downloads\\invoice.pdf.exe",
            "SHA256": "def456",
        }
        raw = normalize_row(row, "DeviceFileEvents")["raw"]
        self.assertEqual(raw["UsnReasonTokens"], ["RENAME_NEW_NAME"])
        self.assertEqual(raw["PreviousFileFullPath"], "C:\\Users\\v\\Downloads\\invoice.pdf.exe")

    def test_registry_sets_keypath(self) -> None:
        row = {
            "Timestamp": "2026-07-06T10:00:00Z", "DeviceName": "WKS-01",
            "ActionType": "RegistryValueSet",
            "RegistryKey": "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            "RegistryValueName": "Updater",
            "RegistryValueData": "C:\\Users\\v\\payload.exe",
            "InitiatingProcessFileName": "payload.exe",
        }
        ev = normalize_row(row, "DeviceRegistryEvents")
        self.assertEqual(ev["category"], "persistence")
        self.assertIn("CurrentVersion\\Run", ev["raw"]["KeyPath"])

    def test_logon_event(self) -> None:
        row = {
            "Timestamp": "2026-07-06T10:00:00Z", "DeviceName": "WKS-01",
            "ActionType": "LogonSuccess", "AccountName": "v",
            "AccountDomain": "CORP", "LogonType": "RemoteInteractive",
            "RemoteIP": "198.51.100.7",
        }
        ev = normalize_row(row, "DeviceLogonEvents")
        self.assertEqual(ev["category"], "account")
        self.assertEqual(ev["entity"], "v")
        self.assertIn("198.51.100.7", ev["summary"])

    def test_browser_launched_url(self) -> None:
        row = {
            "Timestamp": "2026-07-06T10:00:00Z", "DeviceName": "WKS-01",
            "ActionType": "BrowserLaunchedToOpenUrl",
            "RemoteUrl": "https://evil.example/landing",
            "InitiatingProcessFileName": "chrome.exe",
        }
        ev = normalize_row(row, "DeviceEvents")
        self.assertEqual(ev["category"], "browser")
        self.assertEqual(ev["raw"]["Url"], "https://evil.example/landing")

    def test_csv_export_with_utf8_bom_parses_timestamp(self) -> None:
        # Defender portal CSV exports are UTF-8 with a BOM and Timestamp is the
        # first column. Without utf-8-sig the BOM mangles the header to
        # "﻿Timestamp", nulling the timestamp -> the event would be missing
        # from the timeline (which requires a timestamp) though it shows in Events.
        import tempfile
        from pathlib import Path
        from app.ingest.parsers import parse_file

        body = (
            "Timestamp,DeviceName,ActionType,FileName,FolderPath,InitiatingProcessFileName\r\n"
            "2026-04-14T13:20:00.7654321Z,WKS-01,FileCreated,a.exe,C:\\x\\a.exe,chrome.exe\r\n"
        )
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "DeviceFileEvents.csv"
            p.write_bytes(b"\xef\xbb\xbf" + body.encode("utf-8"))
            ev = list(parse_file(p, "DeviceFileEvents"))[0]
        self.assertIsNotNone(ev["timestamp"], "BOM should not null the timestamp")
        self.assertIn("Timestamp", ev["raw"])
        self.assertNotIn("﻿Timestamp", ev["raw"])

    def test_unknown_table_generic_fallback(self) -> None:
        # An unmodeled Device*/AH table is still ingested best-effort, with host
        # attributed and all columns retained in raw (nothing dropped).
        row = {
            "Timestamp": "2026-07-06T10:00:00Z", "DeviceName": "WKS-01",
            "ActionType": "AntivirusDetection", "ThreatName": "Trojan:Win32/Foo",
            "InitiatingProcessFileName": "explorer.exe",
        }
        ev = normalize_row(row, "DeviceTvmSomethingNew")
        self.assertEqual(ev["host"], "WKS-01")
        self.assertEqual(ev["raw"]["ThreatName"], "Trojan:Win32/Foo")
        self.assertTrue(ev["summary"])


if __name__ == "__main__":
    unittest.main()
