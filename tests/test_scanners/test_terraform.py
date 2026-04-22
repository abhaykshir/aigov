from __future__ import annotations

from pathlib import Path

import pytest

from aigov.scanners.infra.terraform import TerraformScanner
from aigov.core.models import AISystemType, DeploymentType

FIXTURES = Path(__file__).parent.parent / "fixtures" / "sample_infra"


@pytest.fixture(scope="module")
def scanner() -> TerraformScanner:
    return TerraformScanner()


@pytest.fixture(scope="module")
def records(scanner):
    return scanner.scan([str(FIXTURES)])


def _by_type(records, resource_type: str):
    return [
        r for r in records
        if r.tags.get("terraform_resource_type", "").startswith(resource_type)
    ]


# ---------------------------------------------------------------------------
# Scanner properties
# ---------------------------------------------------------------------------

class TestTerraformScannerProperties:
    def test_name(self, scanner):
        assert scanner.name == "infra.terraform"

    def test_description_nonempty(self, scanner):
        assert len(scanner.description) > 10

    def test_does_not_require_credentials(self, scanner):
        assert scanner.requires_credentials is False

    def test_registered_in_engine(self):
        from aigov.core.engine import _registry
        assert "infra.terraform" in _registry()

    def test_enabled_by_default(self):
        from aigov.core.engine import _OPT_IN_SCANNERS
        assert "infra.terraform" not in _OPT_IN_SCANNERS


# ---------------------------------------------------------------------------
# AWS resource detection
# ---------------------------------------------------------------------------

class TestAWSResources:
    def test_sagemaker_endpoint_detected(self, records):
        sm = _by_type(records, "aws_sagemaker_endpoint")
        assert len(sm) >= 1

    def test_sagemaker_resource_name_extracted(self, records):
        sm = _by_type(records, "aws_sagemaker_endpoint")
        names = [r.tags.get("terraform_resource_name") for r in sm]
        assert "inference" in names

    def test_bedrock_agent_detected(self, records):
        bedrock = _by_type(records, "aws_bedrock_agent")
        assert len(bedrock) >= 1

    def test_bedrock_agent_name_extracted(self, records):
        bedrock = _by_type(records, "aws_bedrock_agent")
        names = [r.tags.get("terraform_resource_name") for r in bedrock]
        assert "research_assistant" in names

    def test_aws_provider_set(self, records):
        aws = [r for r in records if r.provider == "AWS"]
        assert len(aws) >= 2

    def test_aws_jurisdiction_is_us(self, records):
        aws = [r for r in records if r.provider == "AWS"]
        assert all(r.tags.get("origin_jurisdiction") == "US" for r in aws)

    def test_bedrock_agent_is_agent_type(self, records):
        bedrock = _by_type(records, "aws_bedrock_agent")
        assert all(r.system_type == AISystemType.AGENT for r in bedrock)


# ---------------------------------------------------------------------------
# GCP resource detection
# ---------------------------------------------------------------------------

class TestGCPResources:
    def test_vertex_ai_endpoint_detected(self, records):
        vertex = _by_type(records, "google_vertex_ai_")
        assert len(vertex) >= 1

    def test_vertex_resource_name_extracted(self, records):
        vertex = _by_type(records, "google_vertex_ai_")
        names = [r.tags.get("terraform_resource_name") for r in vertex]
        assert "classification" in names

    def test_gcp_provider_set(self, records):
        gcp = [r for r in records if r.provider == "GCP"]
        assert len(gcp) >= 1

    def test_gcp_jurisdiction_is_us(self, records):
        gcp = [r for r in records if r.provider == "GCP"]
        assert all(r.tags.get("origin_jurisdiction") == "US" for r in gcp)


# ---------------------------------------------------------------------------
# Azure resource detection
# ---------------------------------------------------------------------------

class TestAzureResources:
    def test_cognitive_account_detected(self, records):
        azure = _by_type(records, "azurerm_cognitive_account")
        assert len(azure) >= 1

    def test_cognitive_account_name_extracted(self, records):
        azure = _by_type(records, "azurerm_cognitive_account")
        names = [r.tags.get("terraform_resource_name") for r in azure]
        assert "openai" in names

    def test_azure_provider_set(self, records):
        azure = [r for r in records if r.provider == "Azure"]
        assert len(azure) >= 1

    def test_azure_cognitive_is_api_service(self, records):
        azure = _by_type(records, "azurerm_cognitive_account")
        assert all(r.system_type == AISystemType.API_SERVICE for r in azure)


# ---------------------------------------------------------------------------
# Nested module detection
# ---------------------------------------------------------------------------

class TestNestedModules:
    def test_sagemaker_model_in_module_detected(self, records):
        sm_model = _by_type(records, "aws_sagemaker_model")
        assert len(sm_model) >= 1

    def test_sagemaker_training_job_in_module_detected(self, records):
        sm_train = _by_type(records, "aws_sagemaker_training_job")
        assert len(sm_train) >= 1

    def test_module_resource_names_extracted(self, records):
        sm_model = _by_type(records, "aws_sagemaker_model")
        names = [r.tags.get("terraform_resource_name") for r in sm_model]
        assert "pipeline_model" in names


# ---------------------------------------------------------------------------
# Non-AI resource exclusion
# ---------------------------------------------------------------------------

class TestNonAIExclusion:
    def test_s3_bucket_not_detected(self, records):
        s3 = [r for r in records if "s3" in r.tags.get("terraform_resource_type", "").lower()]
        assert len(s3) == 0

    def test_s3_bucket_name_not_in_results(self, records):
        names = [r.tags.get("terraform_resource_name", "") for r in records]
        assert "artifacts" not in names


# ---------------------------------------------------------------------------
# Deployment type and confidence
# ---------------------------------------------------------------------------

class TestDeploymentTypeAndConfidence:
    def test_all_records_are_cloud_api(self, records):
        assert all(r.deployment_type == DeploymentType.CLOUD_API for r in records)

    def test_confidence_is_095(self, records):
        assert all(r.confidence == 0.95 for r in records)

    def test_source_scanner_set(self, records):
        assert all(r.source_scanner == "infra.terraform" for r in records)

    def test_record_ids_unique(self, records):
        ids = [r.id for r in records]
        assert len(ids) == len(set(ids))
