"""The vault integration: what an identity may do in HashiCorp Vault."""

from __future__ import annotations

from hallpass.integrations.vault.vault import Vault, VaultConnection

__all__ = ["INTEGRATION", "Vault", "VaultConnection"]

INTEGRATION = Vault()
