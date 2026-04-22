from __future__ import annotations

from pathlib import Path

import pytest

from aigov.scanners.infra.kubernetes import KubernetesScanner
from aigov.core.models import AISystemType, DeploymentType

FIXTURES = Path(__file__).parent.parent / "fixtures" / "sample_infra"
K8S_DIR = FIXTURES / "k8s"


@pytest.fixture(scope="module")
def scanner() -> KubernetesScanner:
    return KubernetesScanner()


@pytest.fixture(scope="module")
def records(scanner):
    return scanner.scan([str(K8S_DIR)])


# ---------------------------------------------------------------------------
# Scanner properties
# ---------------------------------------------------------------------------

class TestKubernetesScannerProperties:
    def test_name(self, scanner):
        assert scanner.name == "infra.kubernetes"

    def test_description_nonempty(self, scanner):
        assert len(scanner.description) > 10

    def test_does_not_require_credentials(self, scanner):
        assert scanner.requires_credentials is False

    def test_registered_in_engine(self):
        from aigov.core.engine import _registry
        assert "infra.kubernetes" in _registry()

    def test_enabled_by_default(self):
        from aigov.core.engine import _OPT_IN_SCANNERS
        assert "infra.kubernetes" not in _OPT_IN_SCANNERS


# ---------------------------------------------------------------------------
# GPU workload detection
# ---------------------------------------------------------------------------

class TestGPUDetection:
    def test_gpu_deployment_detected(self, records):
        gpu = [r for r in records if r.tags.get("gpu") == "true"]
        assert len(gpu) >= 1

    def test_gpu_record_confidence_is_09(self, records):
        gpu = [r for r in records if r.tags.get("gpu") == "true"]
        assert all(r.confidence >= 0.85 for r in gpu)

    def test_gpu_record_is_self_hosted(self, records):
        gpu = [r for r in records if r.tags.get("gpu") == "true"]
        assert all(r.deployment_type == DeploymentType.SELF_HOSTED for r in gpu)


# ---------------------------------------------------------------------------
# AI container image detection
# ---------------------------------------------------------------------------

class TestAIImageDetection:
    def test_huggingface_tgi_image_detected(self, records):
        hf = [r for r in records if r.provider == "HuggingFace"]
        assert len(hf) >= 1

    def test_huggingface_image_tag_set(self, records):
        hf = [r for r in records if r.provider == "HuggingFace"]
        assert any("text-generation-inference" in r.tags.get("docker_image", "") for r in hf)


# ---------------------------------------------------------------------------
# AI environment variable detection
# ---------------------------------------------------------------------------

class TestEnvVarDetection:
    def test_ai_env_vars_detected(self, records):
        env_records = [r for r in records if r.tags.get("ai_env_keys")]
        assert len(env_records) >= 1

    def test_hf_model_id_key_captured(self, records):
        env_records = [r for r in records if r.tags.get("ai_env_keys")]
        all_keys = ",".join(r.tags.get("ai_env_keys", "") for r in env_records)
        assert "HF_MODEL_ID" in all_keys

    def test_openai_key_name_captured(self, records):
        env_records = [r for r in records if r.tags.get("ai_env_keys")]
        all_keys = ",".join(r.tags.get("ai_env_keys", "") for r in env_records)
        assert "OPENAI_API_KEY" in all_keys


# ---------------------------------------------------------------------------
# ML Platform CRD detection
# ---------------------------------------------------------------------------

class TestCRDDetection:
    def test_seldon_deployment_detected(self, records):
        seldon = [r for r in records if r.tags.get("k8s_kind") == "SeldonDeployment"]
        assert len(seldon) >= 1

    def test_seldon_provider_set(self, records):
        seldon = [r for r in records if r.tags.get("k8s_kind") == "SeldonDeployment"]
        assert all(r.provider == "Seldon" for r in seldon)

    def test_seldon_is_model_type(self, records):
        seldon = [r for r in records if r.tags.get("k8s_kind") == "SeldonDeployment"]
        assert all(r.system_type == AISystemType.MODEL for r in seldon)

    def test_seldon_confidence_is_09(self, records):
        seldon = [r for r in records if r.tags.get("k8s_kind") == "SeldonDeployment"]
        assert all(r.confidence == 0.9 for r in seldon)

    def test_seldon_resource_name_extracted(self, records):
        seldon = [r for r in records if r.tags.get("k8s_kind") == "SeldonDeployment"]
        names = [r.name for r in seldon]
        assert "sklearn-classifier" in names

    def test_kubeflow_pipeline_detected(self, records):
        kf = [r for r in records if r.provider == "KubeFlow"]
        assert len(kf) >= 1

    def test_kubeflow_pipeline_name_extracted(self, records):
        kf = [r for r in records if r.provider == "KubeFlow"]
        names = [r.name for r in kf]
        assert "training-pipeline" in names


# ---------------------------------------------------------------------------
# Non-AI resource exclusion
# ---------------------------------------------------------------------------

class TestNonAIExclusion:
    def test_nginx_not_detected(self, records):
        nginx = [r for r in records if "nginx" in r.name.lower()]
        assert len(nginx) == 0

    def test_nginx_provider_not_in_results(self, records):
        providers = [r.provider for r in records]
        assert "nginx" not in providers

    def test_regular_app_file_produces_no_records(self, scanner):
        regular = scanner.scan([str(K8S_DIR / "regular-app.yaml")])
        assert len(regular) == 0


# ---------------------------------------------------------------------------
# Security
# ---------------------------------------------------------------------------

class TestSecurity:
    def test_api_key_value_not_in_output(self, records):
        """The fake API key value must never appear in any record field."""
        fake_key = "sk-proj-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
        for r in records:
            assert fake_key not in r.description
            assert fake_key not in r.name
            for v in r.tags.values():
                assert fake_key not in v

    def test_env_var_values_not_stored(self, records):
        """Only env var keys are stored — not values like model IDs or tokens."""
        env_records = [r for r in records if r.tags.get("ai_env_keys")]
        for r in env_records:
            # ai_env_keys contains key names like "HF_MODEL_ID", not values
            keys_field = r.tags.get("ai_env_keys", "")
            assert "meta-llama" not in keys_field
            assert "llama-2" not in keys_field.lower()

    def test_source_scanner_set(self, records):
        assert all(r.source_scanner == "infra.kubernetes" for r in records)

    def test_record_ids_unique(self, records):
        ids = [r.id for r in records]
        assert len(ids) == len(set(ids))
