from __future__ import annotations

import hashlib
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import NamedTuple

import yaml

from aigov.core.models import AISystemRecord, AISystemType, DeploymentType
from aigov.scanners.base import BaseScanner

# ---------------------------------------------------------------------------
# Detection tables
# ---------------------------------------------------------------------------

class _ImageDef(NamedTuple):
    provider: str
    system_type: AISystemType


# Prefix → (provider, system_type).  Checked in order; first match wins.
_AI_BASE_IMAGES: list[tuple[str, _ImageDef]] = [
    ("vllm/",                     _ImageDef("vLLM",         AISystemType.API_SERVICE)),
    ("ollama/",                   _ImageDef("Ollama",        AISystemType.API_SERVICE)),
    ("huggingface/text-generation-inference", _ImageDef("HuggingFace", AISystemType.API_SERVICE)),
    ("huggingface/",              _ImageDef("HuggingFace",   AISystemType.MODEL)),
    ("pytorch/pytorch",           _ImageDef("PyTorch",       AISystemType.MODEL)),
    ("tensorflow/tensorflow",     _ImageDef("TensorFlow",    AISystemType.MODEL)),
    ("nvidia/cuda",               _ImageDef("NVIDIA",        AISystemType.MODEL)),
    ("nvcr.io/nvidia/tritonserver", _ImageDef("NVIDIA",     AISystemType.API_SERVICE)),
]

_MODEL_EXTENSIONS: frozenset[str] = frozenset(
    {".onnx", ".safetensors", ".gguf", ".pt", ".bin", ".h5", ".pkl"}
)

class _PkgDef(NamedTuple):
    provider: str
    system_type: AISystemType

_AI_PIP_PACKAGES: list[tuple[str, _PkgDef]] = [
    ("openai",        _PkgDef("OpenAI",       AISystemType.API_SERVICE)),
    ("anthropic",     _PkgDef("Anthropic",    AISystemType.API_SERVICE)),
    ("transformers",  _PkgDef("HuggingFace",  AISystemType.MODEL)),
    ("torch",         _PkgDef("PyTorch",       AISystemType.MODEL)),
    ("tensorflow",    _PkgDef("TensorFlow",   AISystemType.MODEL)),
    ("langchain",     _PkgDef("LangChain",    AISystemType.AGENT)),
    ("vllm",          _PkgDef("vLLM",         AISystemType.API_SERVICE)),
    ("triton",        _PkgDef("NVIDIA",        AISystemType.API_SERVICE)),
]

# Regex: package name at word boundary, ignoring version pins
_PIP_RE = re.compile(
    r"(?:pip(?:3)?\s+install|conda\s+install)\s+[^\\]*?(?<![=<>!])("
    + "|".join(re.escape(p) for p, _ in _AI_PIP_PACKAGES)
    + r")\b",
    re.IGNORECASE,
)

_JURISDICTION: dict[str, str] = {
    "OpenAI":      "US",
    "Anthropic":   "US",
    "HuggingFace": "US",
    "PyTorch":     "US",
    "TensorFlow":  "US",
    "LangChain":   "US",
    "vLLM":        "US",
    "NVIDIA":      "US",
    "Ollama":      "US",
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _now() -> datetime:
    return datetime.now(timezone.utc)


def _record_id(source_scanner: str, location: str, name: str, provider: str, system_type: str) -> str:
    raw = f"{source_scanner}|{location}|{name}|{provider}|{system_type}"
    return hashlib.sha1(raw.encode(), usedforsecurity=False).hexdigest()[:16]


def _match_image(image: str) -> _ImageDef | None:
    img = image.lower().split(":")[0]
    for prefix, defn in _AI_BASE_IMAGES:
        if img.startswith(prefix) or prefix in img:
            return defn
    return None


def _make_record(
    name: str,
    description: str,
    location: str,
    provider: str,
    system_type: AISystemType,
    confidence: float,
    extra_tags: dict[str, str] | None = None,
) -> AISystemRecord:
    tags = {"origin_jurisdiction": _JURISDICTION.get(provider, "XX")}
    if extra_tags:
        tags.update(extra_tags)
    return AISystemRecord(
        id=_record_id("infra.docker", location, name, provider, system_type.value),
        name=name,
        description=description,
        source_scanner="infra.docker",
        source_location=location,
        discovery_timestamp=_now(),
        confidence=confidence,
        system_type=system_type,
        provider=provider,
        deployment_type=DeploymentType.SELF_HOSTED,
        tags=tags,
    )


# ---------------------------------------------------------------------------
# Dockerfile parsing
# ---------------------------------------------------------------------------

def _scan_dockerfile(path: Path) -> list[AISystemRecord]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []

    records: list[AISystemRecord] = []
    seen: set[tuple[str, str]] = set()
    location = str(path)

    # Join backslash-continued lines so multi-line RUN commands are scanned whole
    joined_lines: list[str] = []
    pending = ""
    for raw_line in text.splitlines():
        if raw_line.rstrip().endswith("\\"):
            pending += raw_line.rstrip()[:-1] + " "
        else:
            joined_lines.append(pending + raw_line)
            pending = ""
    if pending:
        joined_lines.append(pending)

    for line in joined_lines:
        stripped = line.strip()

        # FROM <image>
        if stripped.upper().startswith("FROM "):
            image = stripped.split()[1]
            defn = _match_image(image)
            if defn:
                key = (defn.provider, defn.system_type.value)
                if key not in seen:
                    seen.add(key)
                    records.append(_make_record(
                        name=image.split(":")[0].split("/")[-1],
                        description=f"AI base image {image!r} in {path.name}",
                        location=location,
                        provider=defn.provider,
                        system_type=defn.system_type,
                        confidence=0.9,
                        extra_tags={"docker_image": image, "source": "FROM"},
                    ))

        # COPY / ADD — model file transfers
        if stripped.upper().startswith(("COPY ", "ADD ")):
            parts = stripped.split()
            for part in parts[1:]:
                ext = os.path.splitext(part)[1].lower()
                if ext in _MODEL_EXTENSIONS:
                    key = ("model_file", ext)
                    if key not in seen:
                        seen.add(key)
                        records.append(_make_record(
                            name=f"model file ({ext})",
                            description=f"Model file {part!r} copied in {path.name}",
                            location=location,
                            provider="unknown",
                            system_type=AISystemType.MODEL,
                            confidence=0.85,
                            extra_tags={"model_extension": ext, "source": "COPY/ADD"},
                        ))

        # RUN pip/conda install
        if "install" in stripped.lower():
            for pkg_name, pkg_def in _AI_PIP_PACKAGES:
                pattern = re.compile(
                    r"(?:pip(?:3)?\s+install|conda\s+install).*?\b" + re.escape(pkg_name) + r"\b",
                    re.IGNORECASE,
                )
                if pattern.search(stripped):
                    key = (pkg_def.provider, pkg_def.system_type.value)
                    if key not in seen:
                        seen.add(key)
                        records.append(_make_record(
                            name=pkg_name,
                            description=f"AI package {pkg_name!r} installed in {path.name}",
                            location=location,
                            provider=pkg_def.provider,
                            system_type=pkg_def.system_type,
                            confidence=0.8,
                            extra_tags={"pip_package": pkg_name, "source": "RUN"},
                        ))

    return records


# ---------------------------------------------------------------------------
# docker-compose parsing
# ---------------------------------------------------------------------------

def _scan_compose(path: Path) -> list[AISystemRecord]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
        data = yaml.safe_load(text)
    except Exception:  # noqa: BLE001
        return []

    if not isinstance(data, dict):
        return []

    services = data.get("services") or {}
    if not isinstance(services, dict):
        return []

    records: list[AISystemRecord] = []
    location = str(path)

    for svc_name, svc in services.items():
        if not isinstance(svc, dict):
            continue

        image = svc.get("image", "")
        has_gpu = _service_has_gpu(svc)

        if image:
            defn = _match_image(image)
            if defn:
                tags: dict[str, str] = {
                    "origin_jurisdiction": _JURISDICTION.get(defn.provider, "XX"),
                    "docker_image": image,
                    "compose_service": svc_name,
                }
                if has_gpu:
                    tags["gpu"] = "true"
                records.append(_make_record(
                    name=svc_name,
                    description=f"AI service {svc_name!r} using image {image!r}",
                    location=location,
                    provider=defn.provider,
                    system_type=defn.system_type,
                    confidence=0.9,
                    extra_tags=tags,
                ))
        elif has_gpu:
            # Service has GPU reservation but image is built locally — still noteworthy
            records.append(_make_record(
                name=svc_name,
                description=f"Service {svc_name!r} with GPU reservation in {path.name}",
                location=location,
                provider="unknown",
                system_type=AISystemType.MODEL,
                confidence=0.75,
                extra_tags={
                    "gpu": "true",
                    "compose_service": svc_name,
                    "source": "gpu_reservation",
                },
            ))

    return records


def _service_has_gpu(svc: dict) -> bool:
    """Return True if a compose service requests GPU resources."""
    # deploy.resources.reservations.devices[].driver == nvidia
    try:
        devices = (
            svc.get("deploy", {})
               .get("resources", {})
               .get("reservations", {})
               .get("devices", [])
        )
        for device in devices or []:
            if isinstance(device, dict):
                driver = device.get("driver", "")
                caps = device.get("capabilities", [])
                if driver == "nvidia" or "gpu" in (caps or []):
                    return True
    except (AttributeError, TypeError):
        pass
    # runtime: nvidia (older compose syntax)
    return svc.get("runtime") == "nvidia"


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

_DOCKERFILE_NAME_RE = re.compile(r"^Dockerfile(\..*)?$", re.IGNORECASE)
_COMPOSE_NAME_RE = re.compile(r"^docker-compose(\..*)?\.ya?ml$", re.IGNORECASE)


class DockerScanner(BaseScanner):
    @property
    def name(self) -> str:
        return "infra.docker"

    @property
    def description(self) -> str:
        return (
            "Scans Dockerfiles and docker-compose files for AI base images, "
            "model files, AI pip installs, and GPU configurations"
        )

    def scan(self, paths: list[str]) -> list[AISystemRecord]:
        records: list[AISystemRecord] = []
        for root_path in paths:
            for dirpath, dirnames, filenames in os.walk(root_path):
                # Skip hidden dirs and common non-source dirs
                dirnames[:] = [
                    d for d in dirnames
                    if not d.startswith(".") and d not in {"node_modules", "__pycache__", ".venv", "venv"}
                ]
                for filename in filenames:
                    fp = Path(dirpath) / filename
                    if _DOCKERFILE_NAME_RE.match(filename):
                        records.extend(_scan_dockerfile(fp))
                    elif _COMPOSE_NAME_RE.match(filename):
                        records.extend(_scan_compose(fp))
        return records
