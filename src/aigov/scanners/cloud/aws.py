from __future__ import annotations

import hashlib
import os
from datetime import datetime, timezone

from aigov.core.models import AISystemRecord, AISystemType, DeploymentType
from aigov.scanners.base import BaseScanner

# ---------------------------------------------------------------------------
# Optional boto3 import — not a hard dependency.
# When absent, the scanner imports cleanly but returns empty results.
# Install with: pip install aigov[aws]
# ---------------------------------------------------------------------------

try:
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError
    _BOTO3_AVAILABLE = True
except ImportError:
    boto3 = None  # type: ignore[assignment]
    ClientError = Exception  # type: ignore[misc, assignment]
    NoCredentialsError = Exception  # type: ignore[misc, assignment]
    _BOTO3_AVAILABLE = False

_PROVIDER = "AWS"


def _record_id(resource_type: str, arn: str) -> str:
    raw = f"cloud.aws|{resource_type}|{arn}"
    return hashlib.sha1(raw.encode()).hexdigest()[:16]


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _warn(msg: str) -> None:
    from rich.console import Console
    Console(stderr=True).print(f"[yellow]Warning:[/yellow] cloud.aws: {msg}")


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

class AwsScanner(BaseScanner):
    @property
    def name(self) -> str:
        return "cloud.aws"

    @property
    def description(self) -> str:
        return "Discovers AI/ML services deployed in AWS accounts"

    @property
    def requires_credentials(self) -> bool:
        return True

    def scan(self, paths: list[str]) -> list[AISystemRecord]:  # noqa: ARG002  paths unused for cloud scanners
        if not _BOTO3_AVAILABLE:
            _warn("boto3 is not installed. Install it with: pip install aigov[aws]")
            return []

        region = (
            os.environ.get("AWS_DEFAULT_REGION")
            or os.environ.get("AWS_REGION")
            or "us-east-1"
        )

        records: list[AISystemRecord] = []
        for scanner_fn in (
            self._scan_bedrock,
            self._scan_sagemaker,
            self._scan_comprehend,
            self._scan_rekognition,
            self._scan_lex,
        ):
            try:
                records.extend(scanner_fn(region))
            except (ClientError, NoCredentialsError) as exc:
                _warn(f"{scanner_fn.__name__}: {exc}")
            except Exception:
                pass  # service unavailable in region or other transient error

        return records

    # ------------------------------------------------------------------
    # Internal client helper
    # ------------------------------------------------------------------

    def _client(self, service: str, region: str):
        return boto3.client(service, region_name=region)

    # ------------------------------------------------------------------
    # Bedrock
    # ------------------------------------------------------------------

    def _scan_bedrock(self, region: str) -> list[AISystemRecord]:
        records: list[AISystemRecord] = []

        try:
            client = self._client("bedrock", region)
        except Exception:
            return []

        # Foundation models — the Bedrock API returns the full regional catalog;
        # there is no API filter for account-level model access status.
        # Records are tagged catalog_only=true to distinguish them from
        # actively provisioned resources (custom models, agents, KBs, guardrails).
        try:
            resp = client.list_foundation_models()
            for m in resp.get("modelSummaries", []):
                model_id = m.get("modelId", "")
                arn = (
                    m.get("modelArn")
                    or f"arn:aws:bedrock:{region}::foundation-model/{model_id}"
                )
                records.append(AISystemRecord(
                    id=_record_id("bedrock-foundation", arn),
                    name=f"Bedrock: {m.get('modelName', model_id)}",
                    description=(
                        f"AWS Bedrock foundation model {model_id} "
                        f"(provider: {m.get('providerName', 'unknown')}) "
                        f"[catalog entry — account access not verified]"
                    ),
                    source_scanner=self.name,
                    source_location=arn,
                    discovery_timestamp=_now(),
                    confidence=0.95,
                    system_type=AISystemType.MODEL,
                    provider=_PROVIDER,
                    deployment_type=DeploymentType.CLOUD_API,
                    model_identifier=model_id,
                    tags={
                        "origin_jurisdiction": "US",
                        "aws_service": "bedrock",
                        "bedrock_model_provider": m.get("providerName", ""),
                        "catalog_only": "true",
                    },
                ))
        except (ClientError, NoCredentialsError) as exc:
            _warn(f"Bedrock foundation models: {exc}")
            return []

        # Custom models (fine-tunes)
        try:
            resp = client.list_custom_models()
            for m in resp.get("modelSummaries", []):
                arn = m.get("modelArn", "")
                records.append(AISystemRecord(
                    id=_record_id("bedrock-custom", arn),
                    name=f"Bedrock Custom: {m.get('modelName', arn)}",
                    description=(
                        f"AWS Bedrock custom model fine-tuned from "
                        f"{m.get('baseModelId', 'unknown base')}"
                    ),
                    source_scanner=self.name,
                    source_location=arn,
                    discovery_timestamp=_now(),
                    confidence=0.95,
                    system_type=AISystemType.FINE_TUNE,
                    provider=_PROVIDER,
                    deployment_type=DeploymentType.CLOUD_API,
                    model_identifier=arn,
                    tags={
                        "origin_jurisdiction": "US",
                        "aws_service": "bedrock",
                        "bedrock_base_model": m.get("baseModelId", ""),
                    },
                ))
        except ClientError:
            pass

        # Agents and knowledge bases share a client
        try:
            agent_client = self._client("bedrock-agent", region)

            try:
                resp = agent_client.list_agents()
                for a in resp.get("agentSummaries", []):
                    agent_id = a.get("agentId", "")
                    arn = (
                        a.get("agentArn")
                        or f"arn:aws:bedrock:{region}::agent/{agent_id}"
                    )
                    records.append(AISystemRecord(
                        id=_record_id("bedrock-agent", arn),
                        name=f"Bedrock Agent: {a.get('agentName', agent_id)}",
                        description=(
                            f"AWS Bedrock Agent "
                            f"(status: {a.get('agentStatus', 'unknown')})"
                        ),
                        source_scanner=self.name,
                        source_location=arn,
                        discovery_timestamp=_now(),
                        confidence=0.95,
                        system_type=AISystemType.AGENT,
                        provider=_PROVIDER,
                        deployment_type=DeploymentType.CLOUD_API,
                        tags={"origin_jurisdiction": "US", "aws_service": "bedrock-agent"},
                    ))
            except ClientError:
                pass

            try:
                resp = agent_client.list_knowledge_bases()
                for kb in resp.get("knowledgeBaseSummaries", []):
                    kb_id = kb.get("knowledgeBaseId", "")
                    arn = (
                        kb.get("knowledgeBaseArn")
                        or f"arn:aws:bedrock:{region}::knowledge-base/{kb_id}"
                    )
                    records.append(AISystemRecord(
                        id=_record_id("bedrock-kb", arn),
                        name=f"Bedrock KB: {kb.get('name', kb_id)}",
                        description=(
                            f"AWS Bedrock Knowledge Base "
                            f"(status: {kb.get('status', 'unknown')})"
                        ),
                        source_scanner=self.name,
                        source_location=arn,
                        discovery_timestamp=_now(),
                        confidence=0.95,
                        system_type=AISystemType.RAG_PIPELINE,
                        provider=_PROVIDER,
                        deployment_type=DeploymentType.CLOUD_API,
                        tags={"origin_jurisdiction": "US", "aws_service": "bedrock-agent"},
                    ))
            except ClientError:
                pass

        except Exception:
            pass

        # Guardrails
        try:
            resp = client.list_guardrails()
            for gr in resp.get("guardrails", []):
                gr_id = gr.get("id", "")
                arn = (
                    gr.get("arn")
                    or f"arn:aws:bedrock:{region}::guardrail/{gr_id}"
                )
                records.append(AISystemRecord(
                    id=_record_id("bedrock-guardrail", arn),
                    name=f"Bedrock Guardrail: {gr.get('name', gr_id)}",
                    description=(
                        f"AWS Bedrock Guardrail "
                        f"(version: {gr.get('version', 'unknown')})"
                    ),
                    source_scanner=self.name,
                    source_location=arn,
                    discovery_timestamp=_now(),
                    confidence=0.95,
                    system_type=AISystemType.OTHER,
                    provider=_PROVIDER,
                    deployment_type=DeploymentType.CLOUD_API,
                    tags={"origin_jurisdiction": "US", "aws_service": "bedrock"},
                ))
        except ClientError:
            pass

        return records

    # ------------------------------------------------------------------
    # SageMaker
    # ------------------------------------------------------------------

    def _scan_sagemaker(self, region: str) -> list[AISystemRecord]:
        records: list[AISystemRecord] = []

        try:
            client = self._client("sagemaker", region)
        except Exception:
            return []

        # Endpoints — credential errors abort the service
        try:
            resp = client.list_endpoints()
            for ep in resp.get("Endpoints", []):
                arn = ep.get("EndpointArn", "")
                records.append(AISystemRecord(
                    id=_record_id("sagemaker-endpoint", arn),
                    name=f"SageMaker Endpoint: {ep.get('EndpointName', arn)}",
                    description=(
                        f"AWS SageMaker inference endpoint "
                        f"(status: {ep.get('EndpointStatus', 'unknown')})"
                    ),
                    source_scanner=self.name,
                    source_location=arn,
                    discovery_timestamp=_now(),
                    confidence=0.95,
                    system_type=AISystemType.API_SERVICE,
                    provider=_PROVIDER,
                    deployment_type=DeploymentType.CLOUD_API,
                    tags={"origin_jurisdiction": "US", "aws_service": "sagemaker"},
                ))
        except (ClientError, NoCredentialsError) as exc:
            _warn(f"SageMaker endpoints: {exc}")
            return []

        # Models
        try:
            resp = client.list_models()
            for m in resp.get("Models", []):
                arn = m.get("ModelArn", "")
                records.append(AISystemRecord(
                    id=_record_id("sagemaker-model", arn),
                    name=f"SageMaker Model: {m.get('ModelName', arn)}",
                    description="AWS SageMaker model definition",
                    source_scanner=self.name,
                    source_location=arn,
                    discovery_timestamp=_now(),
                    confidence=0.95,
                    system_type=AISystemType.MODEL,
                    provider=_PROVIDER,
                    deployment_type=DeploymentType.CLOUD_API,
                    tags={"origin_jurisdiction": "US", "aws_service": "sagemaker"},
                ))
        except ClientError:
            pass

        # Notebook instances
        try:
            resp = client.list_notebook_instances()
            for nb in resp.get("NotebookInstances", []):
                arn = nb.get("NotebookInstanceArn", "")
                records.append(AISystemRecord(
                    id=_record_id("sagemaker-notebook", arn),
                    name=f"SageMaker Notebook: {nb.get('NotebookInstanceName', arn)}",
                    description=(
                        f"AWS SageMaker notebook instance "
                        f"(status: {nb.get('NotebookInstanceStatus', 'unknown')})"
                    ),
                    source_scanner=self.name,
                    source_location=arn,
                    discovery_timestamp=_now(),
                    confidence=0.95,
                    system_type=AISystemType.OTHER,
                    provider=_PROVIDER,
                    deployment_type=DeploymentType.CLOUD_API,
                    tags={"origin_jurisdiction": "US", "aws_service": "sagemaker"},
                ))
        except ClientError:
            pass

        # Training jobs
        try:
            resp = client.list_training_jobs()
            for job in resp.get("TrainingJobSummaries", []):
                arn = job.get("TrainingJobArn", "")
                records.append(AISystemRecord(
                    id=_record_id("sagemaker-training", arn),
                    name=f"SageMaker Training: {job.get('TrainingJobName', arn)}",
                    description=(
                        f"AWS SageMaker training job "
                        f"(status: {job.get('TrainingJobStatus', 'unknown')})"
                    ),
                    source_scanner=self.name,
                    source_location=arn,
                    discovery_timestamp=_now(),
                    confidence=0.95,
                    system_type=AISystemType.MODEL,
                    provider=_PROVIDER,
                    deployment_type=DeploymentType.CLOUD_API,
                    tags={"origin_jurisdiction": "US", "aws_service": "sagemaker"},
                ))
        except ClientError:
            pass

        return records

    # ------------------------------------------------------------------
    # Comprehend
    # ------------------------------------------------------------------

    def _scan_comprehend(self, region: str) -> list[AISystemRecord]:
        records: list[AISystemRecord] = []

        try:
            client = self._client("comprehend", region)
        except Exception:
            return []

        # Custom classifiers — credential errors abort the service
        try:
            resp = client.list_document_classifiers()
            for clf in resp.get("DocumentClassifierPropertiesList", []):
                arn = clf.get("DocumentClassifierArn", "")
                name = arn.split("/")[-1] if "/" in arn else arn
                records.append(AISystemRecord(
                    id=_record_id("comprehend-classifier", arn),
                    name=f"Comprehend Classifier: {name}",
                    description=(
                        f"AWS Comprehend custom document classifier "
                        f"(language: {clf.get('LanguageCode', 'unknown')})"
                    ),
                    source_scanner=self.name,
                    source_location=arn,
                    discovery_timestamp=_now(),
                    confidence=0.95,
                    system_type=AISystemType.MODEL,
                    provider=_PROVIDER,
                    deployment_type=DeploymentType.CLOUD_API,
                    tags={"origin_jurisdiction": "US", "aws_service": "comprehend"},
                ))
        except (ClientError, NoCredentialsError) as exc:
            _warn(f"Comprehend classifiers: {exc}")
            return []

        # Entity recognizers
        try:
            resp = client.list_entity_recognizers()
            for er in resp.get("EntityRecognizerPropertiesList", []):
                arn = er.get("EntityRecognizerArn", "")
                name = arn.split("/")[-1] if "/" in arn else arn
                records.append(AISystemRecord(
                    id=_record_id("comprehend-ner", arn),
                    name=f"Comprehend Recognizer: {name}",
                    description=(
                        f"AWS Comprehend custom entity recognizer "
                        f"(language: {er.get('LanguageCode', 'unknown')})"
                    ),
                    source_scanner=self.name,
                    source_location=arn,
                    discovery_timestamp=_now(),
                    confidence=0.95,
                    system_type=AISystemType.MODEL,
                    provider=_PROVIDER,
                    deployment_type=DeploymentType.CLOUD_API,
                    tags={"origin_jurisdiction": "US", "aws_service": "comprehend"},
                ))
        except ClientError:
            pass

        return records

    # ------------------------------------------------------------------
    # Rekognition
    # ------------------------------------------------------------------

    def _scan_rekognition(self, region: str) -> list[AISystemRecord]:
        records: list[AISystemRecord] = []

        try:
            client = self._client("rekognition", region)
        except Exception:
            return []

        # Collections — credential errors abort the service
        try:
            resp = client.list_collections()
            for coll_id in resp.get("CollectionIds", []):
                arn = f"arn:aws:rekognition:{region}:*:collection/{coll_id}"
                records.append(AISystemRecord(
                    id=_record_id("rekognition-collection", arn),
                    name=f"Rekognition Collection: {coll_id}",
                    description=(
                        "AWS Rekognition face collection for biometric identification"
                    ),
                    source_scanner=self.name,
                    source_location=arn,
                    discovery_timestamp=_now(),
                    confidence=0.95,
                    system_type=AISystemType.MODEL,
                    provider=_PROVIDER,
                    deployment_type=DeploymentType.CLOUD_API,
                    tags={"origin_jurisdiction": "US", "aws_service": "rekognition"},
                ))
        except (ClientError, NoCredentialsError) as exc:
            _warn(f"Rekognition collections: {exc}")
            return []

        # Stream processors
        try:
            resp = client.list_stream_processors()
            for sp in resp.get("StreamProcessors", []):
                sp_name = sp.get("Name", "")
                arn = (
                    sp.get("Arn")
                    or f"arn:aws:rekognition:{region}:*:streamprocessor/{sp_name}"
                )
                records.append(AISystemRecord(
                    id=_record_id("rekognition-stream", arn),
                    name=f"Rekognition Stream: {sp_name}",
                    description="AWS Rekognition stream processor for video analysis",
                    source_scanner=self.name,
                    source_location=arn,
                    discovery_timestamp=_now(),
                    confidence=0.95,
                    system_type=AISystemType.API_SERVICE,
                    provider=_PROVIDER,
                    deployment_type=DeploymentType.CLOUD_API,
                    tags={"origin_jurisdiction": "US", "aws_service": "rekognition"},
                ))
        except ClientError:
            pass

        return records

    # ------------------------------------------------------------------
    # Lex
    # ------------------------------------------------------------------

    def _scan_lex(self, region: str) -> list[AISystemRecord]:
        records: list[AISystemRecord] = []

        try:
            client = self._client("lexv2-models", region)
        except Exception:
            return []

        try:
            resp = client.list_bots()
            for bot in resp.get("botSummaries", []):
                bot_id = bot.get("botId", "")
                arn = f"arn:aws:lex:{region}:*:bot/{bot_id}"
                records.append(AISystemRecord(
                    id=_record_id("lex-bot", arn),
                    name=f"Lex Bot: {bot.get('botName', bot_id)}",
                    description=(
                        f"AWS Lex v2 conversational bot "
                        f"(status: {bot.get('botStatus', 'unknown')})"
                    ),
                    source_scanner=self.name,
                    source_location=arn,
                    discovery_timestamp=_now(),
                    confidence=0.95,
                    system_type=AISystemType.AGENT,
                    provider=_PROVIDER,
                    deployment_type=DeploymentType.CLOUD_API,
                    tags={"origin_jurisdiction": "US", "aws_service": "lex"},
                ))
        except (ClientError, NoCredentialsError) as exc:
            _warn(f"Lex bots: {exc}")

        return records
