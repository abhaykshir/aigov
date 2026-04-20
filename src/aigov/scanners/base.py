from __future__ import annotations

from abc import ABC, abstractmethod

from aigov.core.models import AISystemRecord


class BaseScanner(ABC):
    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable scanner name."""

    @property
    @abstractmethod
    def description(self) -> str:
        """What this scanner looks for."""

    @property
    def requires_credentials(self) -> bool:
        """Whether this scanner needs external credentials to operate."""
        return False

    @abstractmethod
    def scan(self, paths: list[str]) -> list[AISystemRecord]:
        """Scan the given paths and return discovered AI system records.

        Implementations must never log, store, or transmit credential values —
        only record the type and location of any detected secrets per SECURITY.md.
        """
