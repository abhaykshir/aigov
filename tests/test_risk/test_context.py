"""Tests for aigov.core.risk.context.enrich() and its detectors."""
from __future__ import annotations

import os
import shutil
from datetime import datetime, timezone
from pathlib import Path

import pytest

from aigov.core.models import AISystemRecord, AISystemType, DeploymentType
from aigov.core.risk.context import enrich

FIXTURES = Path(__file__).parent / "fixtures"
FASTAPI_FIXTURE = FIXTURES / "fastapi_users_app.py"
BATCH_FIXTURE = FIXTURES / "batch_processor.py"


# ---------------------------------------------------------------------------
# Helpers — keep CI env vars from leaking into environment detection unless a
# test explicitly opts in.
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _clear_ci_env(monkeypatch):
    for var in ("CI", "GITHUB_ACTIONS", "JENKINS_URL", "JENKINS_HOME", "GITLAB_CI"):
        monkeypatch.delenv(var, raising=False)


def _record(source_location: str, name: str = "ai_thing", description: str = "") -> AISystemRecord:
    return AISystemRecord(
        id="r1",
        name=name,
        description=description,
        source_scanner="test.scanner",
        source_location=source_location,
        discovery_timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
        confidence=0.9,
        system_type=AISystemType.API_SERVICE,
        provider="OpenAI",
        deployment_type=DeploymentType.CLOUD_API,
    )


# ---------------------------------------------------------------------------
# Environment detection
# ---------------------------------------------------------------------------

class TestEnvironment:
    def test_prod_path_yields_production(self):
        rec = _record("infra/prod/main.tf:42")
        assert enrich(rec, ["infra/prod"])["environment"] == "production"

    def test_full_word_production_yields_production(self, tmp_path):
        target = tmp_path / "production" / "app.py"
        target.parent.mkdir(parents=True)
        target.write_text("x = 1\n", encoding="utf-8")
        rec = _record(str(target))
        assert enrich(rec, [str(tmp_path)])["environment"] == "production"

    def test_dev_path_yields_development(self, tmp_path):
        target = tmp_path / "dev" / "app.py"
        target.parent.mkdir(parents=True)
        target.write_text("x = 1\n", encoding="utf-8")
        rec = _record(str(target))
        assert enrich(rec, [str(tmp_path)])["environment"] == "development"

    def test_test_path_yields_test(self, tmp_path):
        target = tmp_path / "tests" / "app.py"
        target.parent.mkdir(parents=True)
        target.write_text("x = 1\n", encoding="utf-8")
        rec = _record(str(target))
        assert enrich(rec, [str(tmp_path)])["environment"] == "test"

    def test_staging_path_yields_staging(self, tmp_path):
        target = tmp_path / "staging" / "app.py"
        target.parent.mkdir(parents=True)
        target.write_text("x = 1\n", encoding="utf-8")
        rec = _record(str(target))
        assert enrich(rec, [str(tmp_path)])["environment"] == "staging"

    def test_unknown_path_yields_unknown(self, tmp_path):
        # Path-only signals are absent and CI env vars are cleared by the
        # autouse fixture, so the detector must report "unknown".
        target = tmp_path / "src" / "app.py"
        target.parent.mkdir(parents=True)
        target.write_text("x = 1\n", encoding="utf-8")
        rec = _record(str(target))
        assert enrich(rec, [str(tmp_path)])["environment"] == "unknown"

    def test_dotenv_production_file_dominates(self, tmp_path):
        (tmp_path / ".env.production").write_text("DB=prod\n", encoding="utf-8")
        target = tmp_path / "app.py"
        target.write_text("x = 1\n", encoding="utf-8")
        rec = _record(str(target))
        assert enrich(rec, [str(tmp_path)])["environment"] == "production"

    def test_ci_env_var_falls_back_to_test(self, tmp_path, monkeypatch):
        target = tmp_path / "app.py"
        target.write_text("x = 1\n", encoding="utf-8")
        monkeypatch.setenv("GITHUB_ACTIONS", "true")
        rec = _record(str(target))
        assert enrich(rec, [str(tmp_path)])["environment"] == "test"

    def test_production_wins_over_test_when_both_match(self, tmp_path):
        target = tmp_path / "production" / "test_app.py"
        target.parent.mkdir(parents=True)
        target.write_text("x = 1\n", encoding="utf-8")
        rec = _record(str(target))
        assert enrich(rec, [str(tmp_path)])["environment"] == "production"


# ---------------------------------------------------------------------------
# Exposure detection
# ---------------------------------------------------------------------------

class TestExposure:
    def test_fastapi_yields_public_api(self, tmp_path):
        target = tmp_path / "service.py"
        shutil.copy(FASTAPI_FIXTURE, target)
        rec = _record(str(target))
        assert enrich(rec, [str(tmp_path)])["exposure"] == "public_api"

    def test_flask_yields_public_api(self, tmp_path):
        target = tmp_path / "service.py"
        target.write_text(
            "from flask import Flask\napp = Flask(__name__)\n@app.route('/x')\ndef x(): return 'ok'\n",
            encoding="utf-8",
        )
        rec = _record(str(target))
        assert enrich(rec, [str(tmp_path)])["exposure"] == "public_api"

    def test_django_urlpatterns_yields_public_api(self, tmp_path):
        target = tmp_path / "urls.py"
        target.write_text(
            "from django.urls import path\nurlpatterns = []\n",
            encoding="utf-8",
        )
        rec = _record(str(target))
        assert enrich(rec, [str(tmp_path)])["exposure"] == "public_api"

    def test_express_yields_public_api(self, tmp_path):
        target = tmp_path / "server.js"
        target.write_text(
            "const express = require('express');\nconst app = express();\nrouter.get('/x', h);\n",
            encoding="utf-8",
        )
        rec = _record(str(target))
        assert enrich(rec, [str(tmp_path)])["exposure"] == "public_api"

    def test_no_framework_yields_unknown(self, tmp_path):
        target = tmp_path / "lib.py"
        target.write_text("def add(a, b): return a + b\n", encoding="utf-8")
        rec = _record(str(target))
        assert enrich(rec, [str(tmp_path)])["exposure"] == "unknown"

    def test_batch_path_yields_batch_offline(self, tmp_path):
        target = tmp_path / "batch" / "etl.py"
        target.parent.mkdir(parents=True)
        target.write_text("x = 1\n", encoding="utf-8")
        rec = _record(str(target))
        assert enrich(rec, [str(tmp_path)])["exposure"] == "batch_offline"

    def test_internal_path_with_framework_yields_internal_service(self, tmp_path):
        target = tmp_path / "internal" / "service.py"
        target.parent.mkdir(parents=True)
        shutil.copy(FASTAPI_FIXTURE, target)
        rec = _record(str(target))
        assert enrich(rec, [str(tmp_path)])["exposure"] == "internal_service"

    def test_openapi_file_in_dir_yields_public_api(self, tmp_path):
        (tmp_path / "openapi.json").write_text("{}", encoding="utf-8")
        target = tmp_path / "lib.py"
        target.write_text("x = 1\n", encoding="utf-8")
        rec = _record(str(target))
        assert enrich(rec, [str(tmp_path)])["exposure"] == "public_api"


# ---------------------------------------------------------------------------
# Data sensitivity detection
# ---------------------------------------------------------------------------

class TestDataSensitivity:
    def test_email_keyword_yields_pii(self, tmp_path):
        target = tmp_path / "lib.py"
        target.write_text("def send(email): pass\n", encoding="utf-8")
        rec = _record(str(target))
        cats = enrich(rec, [str(tmp_path)])["data_sensitivity"]
        assert "pii" in cats

    def test_payment_keyword_yields_financial(self, tmp_path):
        target = tmp_path / "lib.py"
        target.write_text("def charge_payment(): pass\n", encoding="utf-8")
        rec = _record(str(target))
        cats = enrich(rec, [str(tmp_path)])["data_sensitivity"]
        assert "financial" in cats

    def test_password_keyword_yields_auth(self, tmp_path):
        target = tmp_path / "lib.py"
        target.write_text("password = get_password()\n", encoding="utf-8")
        rec = _record(str(target))
        cats = enrich(rec, [str(tmp_path)])["data_sensitivity"]
        assert "auth" in cats

    def test_patient_keyword_yields_health(self, tmp_path):
        target = tmp_path / "lib.py"
        target.write_text("def fetch_patient(): pass\n", encoding="utf-8")
        rec = _record(str(target))
        cats = enrich(rec, [str(tmp_path)])["data_sensitivity"]
        assert "health" in cats

    def test_no_sensitive_keywords_yields_empty_list(self, tmp_path):
        target = tmp_path / "lib.py"
        target.write_text("def add(a, b): return a + b\n", encoding="utf-8")
        rec = _record(str(target))
        cats = enrich(rec, [str(tmp_path)])["data_sensitivity"]
        assert cats == []

    def test_multiple_categories_all_returned(self, tmp_path):
        target = tmp_path / "lib.py"
        target.write_text(
            "def handler(email, payment, password): pass\n",
            encoding="utf-8",
        )
        rec = _record(str(target))
        cats = set(enrich(rec, [str(tmp_path)])["data_sensitivity"])
        assert {"pii", "financial", "auth"}.issubset(cats)


# ---------------------------------------------------------------------------
# Interaction type
# ---------------------------------------------------------------------------

class TestInteractionType:
    def test_fastapi_route_yields_user_facing_realtime(self, tmp_path):
        target = tmp_path / "service.py"
        shutil.copy(FASTAPI_FIXTURE, target)
        rec = _record(str(target))
        assert enrich(rec, [str(tmp_path)])["interaction_type"] == "user_facing_realtime"

    def test_batch_processor_yields_batch_offline(self, tmp_path):
        target = tmp_path / "etl.py"
        shutil.copy(BATCH_FIXTURE, target)
        rec = _record(str(target))
        assert enrich(rec, [str(tmp_path)])["interaction_type"] == "batch_offline"

    def test_cli_main_yields_internal_tooling(self, tmp_path):
        target = tmp_path / "cli.py"
        target.write_text(
            "import argparse\nif __name__ == '__main__':\n    print('hi')\n",
            encoding="utf-8",
        )
        rec = _record(str(target))
        # batch fixture has both __main__ and batch_size — here we test pure CLI.
        assert enrich(rec, [str(tmp_path)])["interaction_type"] == "internal_tooling"

    def test_unknown_when_no_signals(self, tmp_path):
        target = tmp_path / "lib.py"
        target.write_text("def add(a, b): return a + b\n", encoding="utf-8")
        rec = _record(str(target))
        assert enrich(rec, [str(tmp_path)])["interaction_type"] == "unknown"


# ---------------------------------------------------------------------------
# Cloud / opaque source locations: path-only heuristics
# ---------------------------------------------------------------------------

class TestCloudFindings:
    def test_arn_does_not_attempt_file_read(self, tmp_path):
        rec = _record("arn:aws:bedrock:us-east-1:123:foundation-model/anthropic.claude")
        # Must not raise; environment should reflect path-only knowledge.
        ctx = enrich(rec, [str(tmp_path)])
        assert ctx["environment"] in {"production", "staging", "development", "test", "unknown"}

    def test_arn_with_prod_token_yields_production(self, tmp_path):
        rec = _record("arn:aws:lambda:us-east-1:123:function:prod-classifier")
        assert enrich(rec, [str(tmp_path)])["environment"] == "production"


# ---------------------------------------------------------------------------
# Security: enrich must not raise on unreadable files or bogus paths
# ---------------------------------------------------------------------------

class TestSecurity:
    def test_nonexistent_file_safe(self, tmp_path):
        rec = _record(str(tmp_path / "does_not_exist.py"))
        ctx = enrich(rec, [str(tmp_path)])
        assert "environment" in ctx
        assert "exposure" in ctx
