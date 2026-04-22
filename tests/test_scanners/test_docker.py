from __future__ import annotations

from pathlib import Path

import pytest

from aigov.scanners.infra.docker import DockerScanner
from aigov.core.models import AISystemType, DeploymentType

FIXTURES = Path(__file__).parent.parent / "fixtures" / "sample_infra"


@pytest.fixture(scope="module")
def scanner() -> DockerScanner:
    return DockerScanner()


@pytest.fixture(scope="module")
def records(scanner):
    return scanner.scan([str(FIXTURES)])


# ---------------------------------------------------------------------------
# Scanner properties
# ---------------------------------------------------------------------------

class TestDockerScannerProperties:
    def test_name(self, scanner):
        assert scanner.name == "infra.docker"

    def test_description_nonempty(self, scanner):
        assert len(scanner.description) > 10

    def test_does_not_require_credentials(self, scanner):
        assert scanner.requires_credentials is False

    def test_registered_in_engine(self):
        from aigov.core.engine import _registry
        assert "infra.docker" in _registry()

    def test_enabled_by_default(self):
        from aigov.core.engine import _OPT_IN_SCANNERS
        assert "infra.docker" not in _OPT_IN_SCANNERS


# ---------------------------------------------------------------------------
# Dockerfile detection
# ---------------------------------------------------------------------------

class TestDockerfileDetection:
    def test_pytorch_base_image_detected(self, records):
        providers = [r.provider for r in records]
        assert "PyTorch" in providers

    def test_pytorch_record_has_correct_type(self, records):
        pytorch = [r for r in records if r.provider == "PyTorch" and r.tags.get("source") == "FROM"]
        assert len(pytorch) >= 1
        assert all(r.system_type == AISystemType.MODEL for r in pytorch)

    def test_pytorch_confidence_is_09(self, records):
        pytorch_from = [
            r for r in records
            if r.provider == "PyTorch" and r.tags.get("source") == "FROM"
        ]
        assert all(r.confidence == 0.9 for r in pytorch_from)

    def test_model_file_onnx_detected(self, records):
        model_files = [r for r in records if r.tags.get("model_extension") == ".onnx"]
        assert len(model_files) >= 1

    def test_model_file_safetensors_detected(self, records):
        model_files = [r for r in records if r.tags.get("model_extension") == ".safetensors"]
        assert len(model_files) >= 1

    def test_pip_install_transformers_detected(self, records):
        pip = [r for r in records if r.tags.get("pip_package") == "transformers"]
        assert len(pip) >= 1

    def test_pip_install_confidence_is_08(self, records):
        pip = [r for r in records if r.tags.get("source") == "RUN"]
        assert all(r.confidence == 0.8 for r in pip)

    def test_ollama_detected(self, records):
        ollama = [r for r in records if r.provider == "Ollama"]
        assert len(ollama) >= 1

    def test_ollama_is_api_service(self, records):
        ollama = [r for r in records if r.provider == "Ollama"]
        assert all(r.system_type == AISystemType.API_SERVICE for r in ollama)


# ---------------------------------------------------------------------------
# docker-compose detection
# ---------------------------------------------------------------------------

class TestDockerComposeDetection:
    def test_vllm_service_detected(self, records):
        vllm = [r for r in records if r.provider == "vLLM"]
        assert len(vllm) >= 1

    def test_vllm_is_api_service(self, records):
        vllm = [r for r in records if r.provider == "vLLM"]
        assert all(r.system_type == AISystemType.API_SERVICE for r in vllm)

    def test_gpu_config_detected(self, records):
        gpu_records = [r for r in records if r.tags.get("gpu") == "true"]
        assert len(gpu_records) >= 1

    def test_compose_service_name_in_tags(self, records):
        compose = [r for r in records if r.tags.get("compose_service") == "vllm"]
        assert len(compose) >= 1

    def test_postgres_not_detected(self, records):
        """postgres is a plain DB service — must not appear in AI scan results."""
        names = [r.name for r in records]
        providers = [r.provider for r in records]
        assert "postgres" not in names
        assert "PostgreSQL" not in providers


# ---------------------------------------------------------------------------
# Deployment type
# ---------------------------------------------------------------------------

class TestDeploymentType:
    def test_all_records_are_self_hosted(self, records):
        assert all(r.deployment_type == DeploymentType.SELF_HOSTED for r in records)


# ---------------------------------------------------------------------------
# Source scanner tag
# ---------------------------------------------------------------------------

class TestSourceScanner:
    def test_source_scanner_set(self, records):
        assert all(r.source_scanner == "infra.docker" for r in records)

    def test_source_location_is_a_path(self, records):
        for r in records:
            assert "/" in r.source_location or "\\" in r.source_location


# ---------------------------------------------------------------------------
# Security
# ---------------------------------------------------------------------------

class TestSecurity:
    def test_no_sensitive_data_in_descriptions(self, records):
        """Descriptions must not contain credential values or raw file content."""
        sensitive_patterns = ["sk-", "password", "secret", "token="]
        for r in records:
            desc_lower = r.description.lower()
            for pattern in sensitive_patterns:
                assert pattern not in desc_lower, (
                    f"Possible sensitive data in description: {r.description!r}"
                )

    def test_no_file_contents_in_tags(self, records):
        for r in records:
            for v in r.tags.values():
                assert len(v) < 500, f"Tag value suspiciously long: {v!r}"

    def test_records_have_ids(self, records):
        ids = [r.id for r in records]
        assert all(ids)
        assert len(ids) == len(set(ids)), "Duplicate record IDs found"
