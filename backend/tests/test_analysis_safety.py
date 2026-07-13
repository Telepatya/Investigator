from __future__ import annotations

import asyncio
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import AsyncMock, patch

import app.config as config
from app.llm import orchestrator
from app.store import cases
from app.store.database import dispose_all_db_engines


class AnalysisSafetyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.old_config_dir = config.DEFAULT_CONFIG_DIR
        self.old_cases_dir = config.DEFAULT_CASES_DIR
        self.old_config_file = config.CONFIG_FILE
        self.old_cases_default = config.AppConfig.model_fields["cases_dir"].default
        config.DEFAULT_CONFIG_DIR = self.root
        config.DEFAULT_CASES_DIR = self.root / "cases"
        config.CONFIG_FILE = self.root / "config.json"
        config.AppConfig.model_fields["cases_dir"].default = str(config.DEFAULT_CASES_DIR)
        self.config_patch = patch.object(
            config,
            "load_config",
            side_effect=lambda: config.AppConfig(cases_dir=str(config.DEFAULT_CASES_DIR)),
        )
        self.orchestrator_config_patch = patch.object(
            orchestrator,
            "load_config",
            side_effect=lambda: config.AppConfig(cases_dir=str(config.DEFAULT_CASES_DIR)),
        )
        self.config_patch.start()
        self.orchestrator_config_patch.start()

    def tearDown(self) -> None:
        dispose_all_db_engines()
        self.orchestrator_config_patch.stop()
        self.config_patch.stop()
        config.DEFAULT_CONFIG_DIR = self.old_config_dir
        config.DEFAULT_CASES_DIR = self.old_cases_dir
        config.CONFIG_FILE = self.old_config_file
        config.AppConfig.model_fields["cases_dir"].default = self.old_cases_default
        self.temp.cleanup()

    def test_empty_case_is_not_assessed_without_calling_a_provider(self) -> None:
        case_id = cases.create_case("empty")["id"]
        with patch.object(
            orchestrator, "get_provider", side_effect=AssertionError("LLM must not run"),
        ):
            result = asyncio.run(orchestrator.analyze_case(case_id))

        self.assertIn("Not assessed", result["summary"])
        self.assertIn("no evidence", result["summary"].lower())
        self.assertNotIn("appears clean", result["summary"].lower())

    def test_automated_analysis_tool_loop_cannot_suppress_findings(self) -> None:
        case_id = cases.create_case("evidence")["id"]
        session = cases.get_session(case_id)
        try:
            cases.add_event(
                session,
                timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
                host="host",
                source="test.log",
                category="process",
                entity="example.exe",
                severity="low",
                summary="Example process event",
                raw={},
            )
            session.commit()
        finally:
            session.close()

        tool_loop = AsyncMock(return_value=("Evidence correlation", []))
        with (
            patch.object(orchestrator, "get_provider", return_value=object()),
            patch.object(orchestrator, "run_tool_loop", tool_loop),
            patch.object(orchestrator, "_extract_ai_findings", AsyncMock(return_value=[])),
            patch.object(
                orchestrator,
                "_complete_json",
                AsyncMock(return_value={
                    "summary": "Evidence requires analyst review.",
                    "timeline_entries": [],
                    "finding_verdicts": [],
                }),
            ),
        ):
            result = asyncio.run(orchestrator.analyze_case(case_id))

        self.assertEqual(result["summary"], "Evidence requires analyst review.")
        self.assertFalse(tool_loop.await_args.kwargs["allow_suppression"])


if __name__ == "__main__":
    unittest.main()
