from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

import aigov.scanners.cloud.aws as aws_module
from aigov.scanners.cloud.aws import AwsScanner
from aigov.core.models import AISystemType, DeploymentType, RiskLevel


# ---------------------------------------------------------------------------
# Helpers — build a mock boto3 client factory
# ---------------------------------------------------------------------------

def _make_client_factory(
    *,
    bedrock_models: list[dict] | None = None,
    bedrock_custom: list[dict] | None = None,
    bedrock_agents: list[dict] | None = None,
    bedrock_kbs: list[dict] | None = None,
    bedrock_guardrails: list[dict] | None = None,
    sagemaker_endpoints: list[dict] | None = None,
    sagemaker_models: list[dict] | None = None,
    sagemaker_notebooks: list[dict] | None = None,
    sagemaker_training: list[dict] | None = None,
    comprehend_classifiers: list[dict] | None = None,
    comprehend_ner: list[dict] | None = None,
    rekognition_collections: list[str] | None = None,
    rekognition_streams: list[dict] | None = None,
    lex_bots: list[dict] | None = None,
):
    def factory(service_name, **kwargs):  # noqa: ARG001
        m = MagicMock()
        if service_name == "bedrock":
            m.list_foundation_models.return_value = {
                "modelSummaries": bedrock_models or []
            }
            m.list_custom_models.return_value = {
                "modelSummaries": bedrock_custom or []
            }
            m.list_guardrails.return_value = {
                "guardrails": bedrock_guardrails or []
            }
        elif service_name == "bedrock-agent":
            m.list_agents.return_value = {
                "agentSummaries": bedrock_agents or []
            }
            m.list_knowledge_bases.return_value = {
                "knowledgeBaseSummaries": bedrock_kbs or []
            }
        elif service_name == "sagemaker":
            m.list_endpoints.return_value = {
                "Endpoints": sagemaker_endpoints or []
            }
            m.list_models.return_value = {
                "Models": sagemaker_models or []
            }
            m.list_notebook_instances.return_value = {
                "NotebookInstances": sagemaker_notebooks or []
            }
            m.list_training_jobs.return_value = {
                "TrainingJobSummaries": sagemaker_training or []
            }
        elif service_name == "comprehend":
            m.list_document_classifiers.return_value = {
                "DocumentClassifierPropertiesList": comprehend_classifiers or []
            }
            m.list_entity_recognizers.return_value = {
                "EntityRecognizerPropertiesList": comprehend_ner or []
            }
        elif service_name == "rekognition":
            m.list_collections.return_value = {
                "CollectionIds": rekognition_collections or []
            }
            m.list_stream_processors.return_value = {
                "StreamProcessors": rekognition_streams or []
            }
        elif service_name == "lexv2-models":
            m.list_bots.return_value = {
                "botSummaries": lex_bots or []
            }
        return m
    return factory


# Standard mock data reused across several tests
_BEDROCK_MODELS = [
    {
        "modelId": "anthropic.claude-3-sonnet-20240229-v1:0",
        "modelName": "Claude 3 Sonnet",
        "providerName": "Anthropic",
        "modelArn": "arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-3-sonnet-20240229-v1:0",
    },
    {
        "modelId": "amazon.titan-text-express-v1",
        "modelName": "Titan Text Express",
        "providerName": "Amazon",
        "modelArn": "arn:aws:bedrock:us-east-1::foundation-model/amazon.titan-text-express-v1",
    },
]

_SAGEMAKER_ENDPOINTS = [
    {
        "EndpointName": "fraud-detection-endpoint",
        "EndpointArn": "arn:aws:sagemaker:us-east-1:123456789012:endpoint/fraud-detection-endpoint",
        "EndpointStatus": "InService",
    }
]

_COMPREHEND_CLASSIFIERS = [
    {
        "DocumentClassifierArn": "arn:aws:comprehend:us-east-1:123456789012:document-classifier/sentiment-v1",
        "LanguageCode": "en",
    }
]

_REKOGNITION_COLLECTIONS = ["employee-faces", "visitor-faces"]

_ALL_EMPTY_FACTORY = _make_client_factory()


# ---------------------------------------------------------------------------
# Basic scanner properties
# ---------------------------------------------------------------------------

class TestAwsScannerProperties:
    def test_name(self):
        assert AwsScanner().name == "cloud.aws"

    def test_description(self):
        assert "AWS" in AwsScanner().description

    def test_requires_credentials(self):
        assert AwsScanner().requires_credentials is True

    def test_is_registered_in_engine(self):
        from aigov.core.engine import _registry
        assert "cloud.aws" in _registry()

    def test_not_in_default_run(self):
        from aigov.core.engine import ScanEngine, _OPT_IN_SCANNERS
        assert "cloud.aws" in _OPT_IN_SCANNERS

    def test_default_scan_excludes_aws(self):
        from aigov.core.engine import ScanEngine
        engine = ScanEngine(paths=["."])
        scanner_names = [s.name for s in engine._scanners]
        assert "cloud.aws" not in scanner_names

    def test_explicitly_requested_includes_aws(self):
        from aigov.core.engine import ScanEngine
        engine = ScanEngine(paths=["."], enabled_scanners=["cloud.aws"])
        assert any(s.name == "cloud.aws" for s in engine._scanners)


# ---------------------------------------------------------------------------
# boto3 not installed
# ---------------------------------------------------------------------------

class TestNoBoto3:
    def test_returns_empty_when_boto3_unavailable(self):
        scanner = AwsScanner()
        with patch.object(aws_module, "_BOTO3_AVAILABLE", False):
            result = scanner.scan(["."])
        assert result == []

    def test_no_crash_when_boto3_unavailable(self):
        scanner = AwsScanner()
        with patch.object(aws_module, "_BOTO3_AVAILABLE", False):
            result = scanner.scan(["."])
        assert isinstance(result, list)


# ---------------------------------------------------------------------------
# Missing credentials
# ---------------------------------------------------------------------------

class TestMissingCredentials:
    def test_no_credentials_returns_empty(self):
        from botocore.exceptions import NoCredentialsError
        scanner = AwsScanner()
        with patch("boto3.client", side_effect=NoCredentialsError()):
            result = scanner.scan(["."])
        assert result == []

    def test_no_credentials_does_not_raise(self):
        from botocore.exceptions import NoCredentialsError
        scanner = AwsScanner()
        with patch("boto3.client", side_effect=NoCredentialsError()):
            scanner.scan(["."])  # must not raise

    def test_client_error_on_first_call_returns_empty_for_that_service(self):
        from botocore.exceptions import ClientError
        scanner = AwsScanner()

        def factory(service_name, **kwargs):
            m = MagicMock()
            if service_name == "bedrock":
                m.list_foundation_models.side_effect = ClientError(
                    {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
                    "ListFoundationModels",
                )
            elif service_name == "sagemaker":
                m.list_endpoints.return_value = {"Endpoints": _SAGEMAKER_ENDPOINTS}
                m.list_models.return_value = {"Models": []}
                m.list_notebook_instances.return_value = {"NotebookInstances": []}
                m.list_training_jobs.return_value = {"TrainingJobSummaries": []}
            elif service_name == "comprehend":
                m.list_document_classifiers.return_value = {"DocumentClassifierPropertiesList": []}
                m.list_entity_recognizers.return_value = {"EntityRecognizerPropertiesList": []}
            elif service_name == "rekognition":
                m.list_collections.return_value = {"CollectionIds": []}
                m.list_stream_processors.return_value = {"StreamProcessors": []}
            elif service_name == "lexv2-models":
                m.list_bots.return_value = {"botSummaries": []}
            return m

        with patch("boto3.client", side_effect=factory):
            result = scanner.scan(["."])

        # Bedrock returned nothing (credential error) but SageMaker still works
        assert any("SageMaker Endpoint" in r.name for r in result)
        assert not any("Bedrock" in r.name for r in result)


# ---------------------------------------------------------------------------
# Bedrock discovery
# ---------------------------------------------------------------------------

class TestBedrockScan:
    def _scan_with(self, **kwargs):
        scanner = AwsScanner()
        factory = _make_client_factory(**kwargs)
        with patch("boto3.client", side_effect=factory):
            return scanner.scan(["."])

    def test_foundation_models_discovered(self):
        result = self._scan_with(bedrock_models=_BEDROCK_MODELS)
        bedrock = [r for r in result if "Bedrock:" in r.name]
        assert len(bedrock) == 2

    def test_foundation_model_names(self):
        result = self._scan_with(bedrock_models=_BEDROCK_MODELS)
        names = {r.name for r in result if "Bedrock:" in r.name}
        assert "Bedrock: Claude 3 Sonnet" in names
        assert "Bedrock: Titan Text Express" in names

    def test_foundation_model_arn_as_source_location(self):
        result = self._scan_with(bedrock_models=_BEDROCK_MODELS)
        for r in result:
            if "Bedrock:" in r.name:
                assert r.source_location.startswith("arn:aws:bedrock")

    def test_foundation_model_system_type_is_model(self):
        result = self._scan_with(bedrock_models=_BEDROCK_MODELS)
        for r in result:
            if "Bedrock:" in r.name:
                assert r.system_type == AISystemType.MODEL

    def test_foundation_model_provider_is_aws(self):
        result = self._scan_with(bedrock_models=_BEDROCK_MODELS)
        for r in result:
            if "Bedrock:" in r.name:
                assert r.provider == "AWS"

    def test_foundation_model_deployment_type(self):
        result = self._scan_with(bedrock_models=_BEDROCK_MODELS)
        for r in result:
            if "Bedrock:" in r.name:
                assert r.deployment_type == DeploymentType.CLOUD_API

    def test_foundation_model_confidence(self):
        result = self._scan_with(bedrock_models=_BEDROCK_MODELS)
        for r in result:
            if "Bedrock:" in r.name:
                assert r.confidence == 0.95

    def test_foundation_model_jurisdiction_us(self):
        result = self._scan_with(bedrock_models=_BEDROCK_MODELS)
        for r in result:
            if "Bedrock:" in r.name:
                assert r.tags["origin_jurisdiction"] == "US"

    def test_foundation_model_aws_service_tag(self):
        result = self._scan_with(bedrock_models=_BEDROCK_MODELS)
        for r in result:
            if "Bedrock:" in r.name:
                assert r.tags["aws_service"] == "bedrock"

    def test_foundation_model_model_identifier_set(self):
        result = self._scan_with(bedrock_models=_BEDROCK_MODELS)
        claude = next(r for r in result if "Claude 3 Sonnet" in r.name)
        assert "claude" in claude.model_identifier.lower()

    def test_bedrock_agent_discovered(self):
        agents = [{"agentId": "abc123", "agentName": "ResumeAgent", "agentStatus": "PREPARED",
                   "agentArn": "arn:aws:bedrock:us-east-1::agent/abc123"}]
        result = self._scan_with(bedrock_models=[], bedrock_agents=agents)
        assert any("ResumeAgent" in r.name for r in result)

    def test_bedrock_agent_system_type(self):
        agents = [{"agentId": "a1", "agentName": "MyAgent", "agentStatus": "PREPARED",
                   "agentArn": "arn:aws:bedrock:us-east-1::agent/a1"}]
        result = self._scan_with(bedrock_models=[], bedrock_agents=agents)
        agent_records = [r for r in result if "MyAgent" in r.name]
        assert agent_records[0].system_type == AISystemType.AGENT

    def test_bedrock_knowledge_base_is_rag_pipeline(self):
        kbs = [{"knowledgeBaseId": "kb1", "name": "ProductDocs", "status": "ACTIVE",
                "knowledgeBaseArn": "arn:aws:bedrock:us-east-1::knowledge-base/kb1"}]
        result = self._scan_with(bedrock_models=[], bedrock_kbs=kbs)
        kb_records = [r for r in result if "ProductDocs" in r.name]
        assert kb_records[0].system_type == AISystemType.RAG_PIPELINE

    def test_custom_model_is_fine_tune(self):
        custom = [{"modelArn": "arn:aws:bedrock:us-east-1:123:custom-model/my-model",
                   "modelName": "my-model", "baseModelId": "amazon.titan-text-v1"}]
        result = self._scan_with(bedrock_models=[], bedrock_custom=custom)
        custom_records = [r for r in result if "my-model" in r.name]
        assert custom_records[0].system_type == AISystemType.FINE_TUNE

    def test_empty_bedrock_returns_no_bedrock_records(self):
        result = self._scan_with()
        assert not any("Bedrock" in r.name for r in result)


# ---------------------------------------------------------------------------
# SageMaker discovery
# ---------------------------------------------------------------------------

class TestSageMakerScan:
    def _scan_with(self, **kwargs):
        scanner = AwsScanner()
        factory = _make_client_factory(**kwargs)
        with patch("boto3.client", side_effect=factory):
            return scanner.scan(["."])

    def test_endpoint_discovered(self):
        result = self._scan_with(sagemaker_endpoints=_SAGEMAKER_ENDPOINTS)
        assert any("fraud-detection-endpoint" in r.name for r in result)

    def test_endpoint_arn_as_source_location(self):
        result = self._scan_with(sagemaker_endpoints=_SAGEMAKER_ENDPOINTS)
        ep = next(r for r in result if "fraud-detection-endpoint" in r.name)
        assert ep.source_location == _SAGEMAKER_ENDPOINTS[0]["EndpointArn"]

    def test_endpoint_system_type(self):
        result = self._scan_with(sagemaker_endpoints=_SAGEMAKER_ENDPOINTS)
        ep = next(r for r in result if "fraud-detection-endpoint" in r.name)
        assert ep.system_type == AISystemType.API_SERVICE

    def test_endpoint_aws_service_tag(self):
        result = self._scan_with(sagemaker_endpoints=_SAGEMAKER_ENDPOINTS)
        ep = next(r for r in result if "fraud-detection-endpoint" in r.name)
        assert ep.tags["aws_service"] == "sagemaker"

    def test_sagemaker_model_discovered(self):
        models = [{"ModelName": "bert-classifier",
                   "ModelArn": "arn:aws:sagemaker:us-east-1:123:model/bert-classifier"}]
        result = self._scan_with(sagemaker_models=models)
        assert any("bert-classifier" in r.name for r in result)

    def test_sagemaker_model_system_type(self):
        models = [{"ModelName": "bert-classifier",
                   "ModelArn": "arn:aws:sagemaker:us-east-1:123:model/bert-classifier"}]
        result = self._scan_with(sagemaker_models=models)
        rec = next(r for r in result if "bert-classifier" in r.name)
        assert rec.system_type == AISystemType.MODEL

    def test_training_job_discovered(self):
        jobs = [{"TrainingJobName": "bert-finetune-v2",
                 "TrainingJobArn": "arn:aws:sagemaker:us-east-1:123:training-job/bert-finetune-v2",
                 "TrainingJobStatus": "Completed"}]
        result = self._scan_with(sagemaker_training=jobs)
        assert any("bert-finetune-v2" in r.name for r in result)


# ---------------------------------------------------------------------------
# Comprehend discovery
# ---------------------------------------------------------------------------

class TestComprehendScan:
    def _scan_with(self, **kwargs):
        scanner = AwsScanner()
        factory = _make_client_factory(**kwargs)
        with patch("boto3.client", side_effect=factory):
            return scanner.scan(["."])

    def test_classifier_discovered(self):
        result = self._scan_with(comprehend_classifiers=_COMPREHEND_CLASSIFIERS)
        assert any("sentiment-v1" in r.name for r in result)

    def test_classifier_arn_as_source_location(self):
        result = self._scan_with(comprehend_classifiers=_COMPREHEND_CLASSIFIERS)
        clf = next(r for r in result if "sentiment-v1" in r.name)
        assert clf.source_location == _COMPREHEND_CLASSIFIERS[0]["DocumentClassifierArn"]

    def test_classifier_system_type(self):
        result = self._scan_with(comprehend_classifiers=_COMPREHEND_CLASSIFIERS)
        clf = next(r for r in result if "sentiment-v1" in r.name)
        assert clf.system_type == AISystemType.MODEL

    def test_classifier_aws_service_tag(self):
        result = self._scan_with(comprehend_classifiers=_COMPREHEND_CLASSIFIERS)
        clf = next(r for r in result if "sentiment-v1" in r.name)
        assert clf.tags["aws_service"] == "comprehend"

    def test_entity_recognizer_discovered(self):
        ner = [{"EntityRecognizerArn": "arn:aws:comprehend:us-east-1:123:entity-recognizer/medical-ner",
                "LanguageCode": "en"}]
        result = self._scan_with(comprehend_ner=ner)
        assert any("medical-ner" in r.name for r in result)


# ---------------------------------------------------------------------------
# Rekognition discovery
# ---------------------------------------------------------------------------

class TestRekognitionScan:
    def _scan_with(self, **kwargs):
        scanner = AwsScanner()
        factory = _make_client_factory(**kwargs)
        with patch("boto3.client", side_effect=factory):
            return scanner.scan(["."])

    def test_collections_discovered(self):
        result = self._scan_with(rekognition_collections=_REKOGNITION_COLLECTIONS)
        collection_records = [r for r in result if "Rekognition Collection" in r.name]
        assert len(collection_records) == 2

    def test_collection_names(self):
        result = self._scan_with(rekognition_collections=_REKOGNITION_COLLECTIONS)
        names = {r.name for r in result if "Rekognition Collection" in r.name}
        assert "Rekognition Collection: employee-faces" in names
        assert "Rekognition Collection: visitor-faces" in names

    def test_collection_arn_as_source_location(self):
        result = self._scan_with(rekognition_collections=["employee-faces"])
        rec = next(r for r in result if "employee-faces" in r.name)
        assert "arn:aws:rekognition" in rec.source_location
        assert "employee-faces" in rec.source_location

    def test_collection_aws_service_tag(self):
        result = self._scan_with(rekognition_collections=["faces"])
        rec = next(r for r in result if "Rekognition Collection" in r.name)
        assert rec.tags["aws_service"] == "rekognition"

    def test_stream_processor_discovered(self):
        streams = [{"Name": "retail-stream", "Arn": "arn:aws:rekognition:us-east-1:123:streamprocessor/retail-stream"}]
        result = self._scan_with(rekognition_streams=streams)
        assert any("retail-stream" in r.name for r in result)


# ---------------------------------------------------------------------------
# Lex discovery
# ---------------------------------------------------------------------------

class TestLexScan:
    def _scan_with(self, **kwargs):
        scanner = AwsScanner()
        factory = _make_client_factory(**kwargs)
        with patch("boto3.client", side_effect=factory):
            return scanner.scan(["."])

    def test_bot_discovered(self):
        bots = [{"botId": "ABCD1234", "botName": "CustomerSupport", "botStatus": "Available"}]
        result = self._scan_with(lex_bots=bots)
        assert any("CustomerSupport" in r.name for r in result)

    def test_bot_arn_as_source_location(self):
        bots = [{"botId": "ABCD1234", "botName": "CustomerSupport", "botStatus": "Available"}]
        result = self._scan_with(lex_bots=bots)
        rec = next(r for r in result if "CustomerSupport" in r.name)
        assert "arn:aws:lex" in rec.source_location
        assert "ABCD1234" in rec.source_location

    def test_bot_system_type_is_agent(self):
        bots = [{"botId": "B1", "botName": "SalesBot", "botStatus": "Available"}]
        result = self._scan_with(lex_bots=bots)
        rec = next(r for r in result if "SalesBot" in r.name)
        assert rec.system_type == AISystemType.AGENT

    def test_bot_aws_service_tag(self):
        bots = [{"botId": "B1", "botName": "SalesBot", "botStatus": "Available"}]
        result = self._scan_with(lex_bots=bots)
        rec = next(r for r in result if "SalesBot" in r.name)
        assert rec.tags["aws_service"] == "lex"


# ---------------------------------------------------------------------------
# Combined / integration-style
# ---------------------------------------------------------------------------

class TestCombinedScan:
    def test_all_five_services_scan_together(self):
        scanner = AwsScanner()
        factory = _make_client_factory(
            bedrock_models=_BEDROCK_MODELS,
            sagemaker_endpoints=_SAGEMAKER_ENDPOINTS,
            comprehend_classifiers=_COMPREHEND_CLASSIFIERS,
            rekognition_collections=_REKOGNITION_COLLECTIONS,
            lex_bots=[{"botId": "B1", "botName": "SalesBot", "botStatus": "Available"}],
        )
        with patch("boto3.client", side_effect=factory):
            result = scanner.scan(["."])

        # 2 Bedrock models + 1 SageMaker endpoint + 1 Comprehend + 2 Rekognition + 1 Lex
        assert len(result) >= 7
        assert any("Bedrock:" in r.name for r in result)
        assert any("SageMaker Endpoint" in r.name for r in result)
        assert any("Comprehend" in r.name for r in result)
        assert any("Rekognition Collection" in r.name for r in result)
        assert any("Lex Bot" in r.name for r in result)

    def test_all_records_have_aws_provider(self):
        scanner = AwsScanner()
        factory = _make_client_factory(
            bedrock_models=_BEDROCK_MODELS,
            sagemaker_endpoints=_SAGEMAKER_ENDPOINTS,
        )
        with patch("boto3.client", side_effect=factory):
            result = scanner.scan(["."])
        for rec in result:
            assert rec.provider == "AWS"

    def test_all_records_have_us_jurisdiction(self):
        scanner = AwsScanner()
        factory = _make_client_factory(
            bedrock_models=_BEDROCK_MODELS,
            rekognition_collections=_REKOGNITION_COLLECTIONS,
        )
        with patch("boto3.client", side_effect=factory):
            result = scanner.scan(["."])
        for rec in result:
            assert rec.tags["origin_jurisdiction"] == "US"

    def test_all_records_have_cloud_api_deployment(self):
        scanner = AwsScanner()
        factory = _make_client_factory(bedrock_models=_BEDROCK_MODELS)
        with patch("boto3.client", side_effect=factory):
            result = scanner.scan(["."])
        for rec in result:
            assert rec.deployment_type == DeploymentType.CLOUD_API

    def test_all_records_have_0_95_confidence(self):
        scanner = AwsScanner()
        factory = _make_client_factory(
            bedrock_models=_BEDROCK_MODELS,
            sagemaker_endpoints=_SAGEMAKER_ENDPOINTS,
        )
        with patch("boto3.client", side_effect=factory):
            result = scanner.scan(["."])
        for rec in result:
            assert rec.confidence == 0.95

    def test_all_records_have_source_scanner(self):
        scanner = AwsScanner()
        factory = _make_client_factory(bedrock_models=_BEDROCK_MODELS)
        with patch("boto3.client", side_effect=factory):
            result = scanner.scan(["."])
        for rec in result:
            assert rec.source_scanner == "cloud.aws"

    def test_all_source_locations_non_empty(self):
        scanner = AwsScanner()
        factory = _make_client_factory(
            bedrock_models=_BEDROCK_MODELS,
            sagemaker_endpoints=_SAGEMAKER_ENDPOINTS,
            comprehend_classifiers=_COMPREHEND_CLASSIFIERS,
            rekognition_collections=_REKOGNITION_COLLECTIONS,
        )
        with patch("boto3.client", side_effect=factory):
            result = scanner.scan(["."])
        for rec in result:
            assert rec.source_location, f"{rec.name} has empty source_location"

    def test_paths_argument_is_ignored(self):
        scanner = AwsScanner()
        factory = _make_client_factory(bedrock_models=_BEDROCK_MODELS)
        with patch("boto3.client", side_effect=factory):
            result_dot = scanner.scan(["."])
            result_paths = scanner.scan(["/some/path", "/other/path"])
        assert len(result_dot) == len(result_paths)

    def test_empty_aws_account_returns_empty_list(self):
        scanner = AwsScanner()
        factory = _make_client_factory()  # all services return empty lists
        with patch("boto3.client", side_effect=factory):
            result = scanner.scan(["."])
        assert result == []

    def test_service_unavailable_in_region_does_not_crash(self):
        from botocore.exceptions import ClientError
        scanner = AwsScanner()

        def factory(service_name, **kwargs):
            m = MagicMock()
            if service_name == "bedrock":
                err = {"Error": {"Code": "UnrecognizedClientException", "Message": "not in region"}}
                m.list_foundation_models.side_effect = ClientError(err, "ListFoundationModels")
            elif service_name == "sagemaker":
                m.list_endpoints.return_value = {"Endpoints": _SAGEMAKER_ENDPOINTS}
                m.list_models.return_value = {"Models": []}
                m.list_notebook_instances.return_value = {"NotebookInstances": []}
                m.list_training_jobs.return_value = {"TrainingJobSummaries": []}
            else:
                m.list_document_classifiers.return_value = {"DocumentClassifierPropertiesList": []}
                m.list_entity_recognizers.return_value = {"EntityRecognizerPropertiesList": []}
                m.list_collections.return_value = {"CollectionIds": []}
                m.list_stream_processors.return_value = {"StreamProcessors": []}
                m.list_bots.return_value = {"botSummaries": []}
                m.list_agents.return_value = {"agentSummaries": []}
                m.list_knowledge_bases.return_value = {"knowledgeBaseSummaries": []}
                m.list_guardrails.return_value = {"guardrails": []}
                m.list_custom_models.return_value = {"modelSummaries": []}
            return m

        with patch("boto3.client", side_effect=factory):
            result = scanner.scan(["."])  # must not raise

        # SageMaker should still work even though Bedrock failed
        assert any("SageMaker Endpoint" in r.name for r in result)


# ---------------------------------------------------------------------------
# Security: no credentials in output
# ---------------------------------------------------------------------------

class TestSecurity:
    def test_source_location_is_arn_not_credential(self):
        scanner = AwsScanner()
        factory = _make_client_factory(bedrock_models=_BEDROCK_MODELS)
        with patch("boto3.client", side_effect=factory):
            result = scanner.scan(["."])
        for rec in result:
            loc = rec.source_location
            # ARN format — not a credential pattern
            assert not loc.startswith("sk-")
            assert not loc.startswith("AKIA")

    def test_tags_contain_no_credential_keys(self):
        scanner = AwsScanner()
        factory = _make_client_factory(
            bedrock_models=_BEDROCK_MODELS,
            sagemaker_endpoints=_SAGEMAKER_ENDPOINTS,
        )
        with patch("boto3.client", side_effect=factory):
            result = scanner.scan(["."])
        for rec in result:
            assert "key_preview" not in rec.tags
            assert "access_key" not in rec.tags
            assert "secret_key" not in rec.tags
