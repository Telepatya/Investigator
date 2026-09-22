from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import patch

from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.api import cases_router
from app.detect import engine, manual, overrides
from app.rules.profile import DEFAULT_PROFILE
from app.rules.safe_regex import UnsafeRegexError
from app.store import cases
from app.store.database import Event, Finding, Process
from test_rules_engine_integration import _IntegrationBase


class DetectionAtomicityTests(_IntegrationBase):
    def seed_prior_results(self):
        case_id = self._seed_case()
        session = cases.get_session(case_id)
        try:
            prior = Finding(title="Prior validated finding", description="Synthetic", severity="high", source="test", evidence={"entity": "synthetic"})
            event = Event(source="synthetic", category="test", summary="benign", severity="high", severity_reason="Detection: prior result", raw={})
            session.add_all([prior, event])
            session.flush()
            manual.add_manual_finding(session, title="Analyst annotation", severity="medium", description="Keep analyst input")
            overrides.set_rule_disabled(session, "synthetic-disabled-rule", True)
            session.commit()
            return case_id, prior.id, event.id
        finally:
            session.close()

    def test_runtime_regex_error_preserves_prior_results_and_process_state(self):
        case_id, prior_id, event_id = self.seed_prior_results()
        profile = replace(DEFAULT_PROFILE, custom=SimpleNamespace(empty=False))

        def fail_on_event(_session, _existing, context, *_args):
            if context.kind == "event":
                raise UnsafeRegexError("synthetic timeout")
            return "high"

        app = FastAPI()
        app.include_router(cases_router.router)
        with patch.object(engine, "load_profile", return_value=profile), patch.object(engine, "_check_custom_rules", side_effect=fail_on_event):
            response = TestClient(app, raise_server_exceptions=False).post(f"/api/cases/{case_id}/detections/run?rebuild=true")
        self.assertEqual(response.status_code, 500)
        session = cases.get_session(case_id)
        try:
            self.assertEqual(session.get(Finding, prior_id).title, "Prior validated finding")
            self.assertEqual(len(list(session.scalars(select(Finding)))), 1)
            event = session.get(Event, event_id)
            self.assertEqual((event.severity, event.severity_reason), ("high", "Detection: prior result"))
            for process in session.scalars(select(Process)):
                self.assertEqual(process.severity, "info")
                self.assertFalse(process.flags)
            self.assertIn("synthetic-disabled-rule", overrides.get_disabled_rules(session))
        finally:
            session.close()

    def test_successful_rebuild_replaces_prior_results_and_keeps_analyst_input(self):
        case_id, _prior_id, event_id = self.seed_prior_results()
        app = FastAPI()
        app.include_router(cases_router.router)
        response = TestClient(app).post(f"/api/cases/{case_id}/detections/run?rebuild=true")
        self.assertEqual(response.status_code, 200, response.text)
        session = cases.get_session(case_id)
        try:
            titles = {row.title for row in session.scalars(select(Finding))}
            self.assertNotIn("Prior validated finding", titles)
            self.assertIn("Analyst annotation", titles)
            self.assertEqual(session.get(Event, event_id).severity, "info")
            self.assertIn("synthetic-disabled-rule", overrides.get_disabled_rules(session))
        finally:
            session.close()
