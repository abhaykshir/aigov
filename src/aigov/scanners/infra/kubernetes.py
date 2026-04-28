from __future__ import annotations

import hashlib
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from aigov.core.models import AISystemRecord, AISystemType, DeploymentType
from aigov.scanners.base import BaseScanner

# ---------------------------------------------------------------------------
# Detection tables
# ---------------------------------------------------------------------------

# AI container image prefixes → (provider, system_type)
_AI_IMAGES: list[tuple[str, str, AISystemType]] = [
    ("vllm/",                           "vLLM",        AISystemType.API_SERVICE),
    ("ollama/",                         "Ollama",       AISystemType.API_SERVICE),
    ("huggingface/text-generation-inference", "HuggingFace", AISystemType.API_SERVICE),
    ("huggingface/",                    "HuggingFace",  AISystemType.MODEL),
    ("pytorch/pytorch",                 "PyTorch",      AISystemType.MODEL),
    ("tensorflow/tensorflow",           "TensorFlow",   AISystemType.MODEL),
    ("nvidia/cuda",                     "NVIDIA",       AISystemType.MODEL),
    ("nvcr.io/nvidia/tritonserver",     "NVIDIA",       AISystemType.API_SERVICE),
]

# Env var key substrings that indicate an AI service credential or config
_AI_ENV_KEYWORDS: frozenset[str] = frozenset({
    "OPENAI", "ANTHROPIC", "HF_MODEL", "HUGGINGFACE",
    "BEDROCK", "SAGEMAKER", "VERTEX", "COHERE", "REPLICATE",
})

# GPU resource keys
_GPU_RESOURCE_KEYS: frozenset[str] = frozenset({"nvidia.com/gpu", "amd.com/gpu"})

# ML platform CRDs: kind → (provider_label, system_type)
_ML_CRDS: dict[str, tuple[str, AISystemType]] = {
    "SeldonDeployment":  ("Seldon",    AISystemType.MODEL),
    "InferenceService":  ("KServe",    AISystemType.MODEL),
    "TFJob":             ("TensorFlow", AISystemType.MODEL),
    "PyTorchJob":        ("PyTorch",   AISystemType.MODEL),
}

# Kubeflow Pipeline needs apiVersion guard to avoid false positives on generic "Pipeline" kinds
_KUBEFLOW_API_PREFIX = "pipelines.kubeflow.org"

_JURISDICTION: dict[str, str] = {
    "vLLM": "US", "Ollama": "US", "HuggingFace": "US",
    "PyTorch": "US", "TensorFlow": "US", "NVIDIA": "US",
    "Seldon": "GB", "KServe": "US",
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _now() -> datetime:
    return datetime.now(timezone.utc)


def _record_id(location: str, name: str, provider: str, system_type: str, suffix: str = "") -> str:
    raw = f"infra.kubernetes|{location}|{name}|{provider}|{system_type}|{suffix}"
    return hashlib.sha1(raw.encode(), usedforsecurity=False).hexdigest()[:16]


def _match_image(image: str) -> tuple[str, AISystemType] | None:
    img = image.lower().split(":")[0]
    for prefix, provider, system_type in _AI_IMAGES:
        if img.startswith(prefix) or prefix.rstrip("/") in img:
            return provider, system_type
    return None


def _make_record(
    name: str,
    description: str,
    location: str,
    provider: str,
    system_type: AISystemType,
    confidence: float,
    extra_tags: dict[str, str] | None = None,
    id_suffix: str = "",
) -> AISystemRecord:
    tags: dict[str, str] = {"origin_jurisdiction": _JURISDICTION.get(provider, "XX")}
    if extra_tags:
        tags.update(extra_tags)
    return AISystemRecord(
        id=_record_id(location, name, provider, system_type.value, id_suffix),
        name=name,
        description=description,
        source_scanner="infra.kubernetes",
        source_location=location,
        discovery_timestamp=_now(),
        confidence=confidence,
        system_type=system_type,
        provider=provider,
        deployment_type=DeploymentType.SELF_HOSTED,
        tags=tags,
    )


# ---------------------------------------------------------------------------
# YAML document analysis
# ---------------------------------------------------------------------------

def _extract_containers(spec: Any) -> list[dict]:
    """Walk a pod spec and collect all container dicts."""
    if not isinstance(spec, dict):
        return []
    containers: list[dict] = []
    template = spec.get("template", {}) or {}
    pod_spec = template.get("spec", {}) or spec.get("spec", {}) or {}
    for key in ("containers", "initContainers"):
        for c in pod_spec.get(key) or []:
            if isinstance(c, dict):
                containers.append(c)
    return containers


def _has_gpu_resources(resources: Any) -> bool:
    if not isinstance(resources, dict):
        return False
    for section in ("limits", "requests"):
        block = resources.get(section) or {}
        if isinstance(block, dict):
            for key in _GPU_RESOURCE_KEYS:
                if key in block:
                    return True
    return False


def _walk_gpu(obj: Any) -> bool:
    """Recursively check any nested dict/list for GPU resource keys."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k in _GPU_RESOURCE_KEYS:
                return True
            if _walk_gpu(v):
                return True
    elif isinstance(obj, list):
        return any(_walk_gpu(item) for item in obj)
    return False


def _env_ai_keys(env_list: Any) -> list[str]:
    """Return AI-related env var names; never include values."""
    found = []
    for item in env_list or []:
        if not isinstance(item, dict):
            continue
        key = item.get("name", "")
        if any(kw in key.upper() for kw in _AI_ENV_KEYWORDS):
            found.append(key)
    return found


def _scan_k8s_doc(doc: dict, path: Path) -> list[AISystemRecord]:
    """Analyse a single parsed Kubernetes YAML document."""
    records: list[AISystemRecord] = []
    location = str(path)

    api_version = str(doc.get("apiVersion", ""))
    kind = str(doc.get("kind", ""))
    meta = doc.get("metadata") or {}
    resource_name = meta.get("name", path.stem)

    # ── ML Platform CRDs ─────────────────────────────────────────────────────
    if kind in _ML_CRDS:
        provider, system_type = _ML_CRDS[kind]
        records.append(_make_record(
            name=resource_name,
            description=f"Kubernetes CRD {kind!r} named {resource_name!r}",
            location=location,
            provider=provider,
            system_type=system_type,
            confidence=0.9,
            extra_tags={"k8s_kind": kind, "k8s_api_version": api_version},
        ))
        return records  # CRD match is definitive; no need to inspect containers

    # ── KubeFlow Pipeline ─────────────────────────────────────────────────────
    if kind == "Pipeline" and _KUBEFLOW_API_PREFIX in api_version:
        records.append(_make_record(
            name=resource_name,
            description=f"KubeFlow Pipeline {resource_name!r}",
            location=location,
            provider="KubeFlow",
            system_type=AISystemType.OTHER,
            confidence=0.9,
            extra_tags={"k8s_kind": kind, "k8s_api_version": api_version},
        ))
        # Also scan pipeline template containers for GPU / AI images
        spec = doc.get("spec") or {}
        for template in spec.get("templates") or []:
            if not isinstance(template, dict):
                continue
            container = template.get("container") or {}
            if _walk_gpu(container.get("resources")):
                records.append(_make_record(
                    name=f"{resource_name}/gpu-step",
                    description=f"GPU step in KubeFlow Pipeline {resource_name!r}",
                    location=location,
                    provider="KubeFlow",
                    system_type=AISystemType.MODEL,
                    confidence=0.85,
                    extra_tags={"k8s_kind": kind, "gpu": "true"},
                ))
                break
        return records

    # ── Standard workloads (Deployment, StatefulSet, DaemonSet, Pod, Job, …) ─
    spec = doc.get("spec") or {}
    containers = _extract_containers(spec)

    # Fall back: if no template containers found, look for top-level containers
    if not containers:
        pod_spec = spec.get("spec") or {}
        for key in ("containers", "initContainers"):
            for c in pod_spec.get(key) or []:
                if isinstance(c, dict):
                    containers.append(c)

    seen_providers: set[str] = set()

    for container in containers:
        image = container.get("image", "")
        env = container.get("env") or []
        resources = container.get("resources") or {}

        # GPU resources
        if _has_gpu_resources(resources):
            tag_key = f"gpu_{resource_name}"
            if tag_key not in seen_providers:
                seen_providers.add(tag_key)
                img_match = _match_image(image) if image else None
                provider = img_match[0] if img_match else "unknown"
                system_type = img_match[1] if img_match else AISystemType.MODEL
                records.append(_make_record(
                    name=resource_name,
                    description=f"GPU workload {resource_name!r} with {kind!r}",
                    location=location,
                    provider=provider,
                    system_type=system_type,
                    confidence=0.9,
                    extra_tags={
                        "gpu": "true",
                        "k8s_kind": kind,
                        **({"docker_image": image} if image else {}),
                    },
                    id_suffix="gpu",
                ))

        # AI container image (non-GPU path)
        if image:
            match = _match_image(image)
            if match:
                provider, system_type = match
                key = f"image_{provider}"
                if key not in seen_providers:
                    seen_providers.add(key)
                    records.append(_make_record(
                        name=resource_name,
                        description=f"AI container image {image!r} in {kind!r} {resource_name!r}",
                        location=location,
                        provider=provider,
                        system_type=system_type,
                        confidence=0.8,
                        extra_tags={"docker_image": image, "k8s_kind": kind},
                        id_suffix="image",
                    ))

        # AI environment variables — keys only, never values
        ai_env_keys = _env_ai_keys(env)
        if ai_env_keys:
            key = f"env_{resource_name}"
            if key not in seen_providers:
                seen_providers.add(key)
                records.append(_make_record(
                    name=resource_name,
                    description=(
                        f"AI-related env vars in {kind!r} {resource_name!r}: "
                        + ", ".join(ai_env_keys)
                    ),
                    location=location,
                    provider="unknown",
                    system_type=AISystemType.API_SERVICE,
                    confidence=0.8,
                    extra_tags={
                        "k8s_kind": kind,
                        "ai_env_keys": ",".join(ai_env_keys),
                    },
                ))

    return records


def _scan_k8s_file(path: Path) -> list[AISystemRecord]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []

    records: list[AISystemRecord] = []
    try:
        for doc in yaml.safe_load_all(text):
            if not isinstance(doc, dict):
                continue
            # Must look like a Kubernetes manifest
            if "apiVersion" not in doc or "kind" not in doc:
                continue
            records.extend(_scan_k8s_doc(doc, path))
    except yaml.YAMLError:
        pass
    return records


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

_YAML_EXTENSIONS = frozenset({".yaml", ".yml"})


class KubernetesScanner(BaseScanner):
    @property
    def name(self) -> str:
        return "infra.kubernetes"

    @property
    def description(self) -> str:
        return (
            "Scans Kubernetes YAML manifests for AI workloads: GPU requests, "
            "AI container images, AI env vars, and ML platform CRDs "
            "(Seldon, KServe, KubeFlow, TFJob, PyTorchJob)"
        )

    def scan(self, paths: list[str]) -> list[AISystemRecord]:
        records: list[AISystemRecord] = []
        for root_path in paths:
            for dirpath, dirnames, filenames in os.walk(root_path):
                dirnames[:] = [
                    d for d in dirnames
                    if not d.startswith(".") and d not in {"__pycache__", ".venv", "venv"}
                ]
                for filename in filenames:
                    if os.path.splitext(filename)[1].lower() in _YAML_EXTENSIONS:
                        records.extend(_scan_k8s_file(Path(dirpath) / filename))
        return records
