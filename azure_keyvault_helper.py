"""
azure_keyvault_helper.py
========================
Azure Key Vault client using SPN (Service Principal / AAD) authentication.

Authentication strategy:
  PRIMARY   → ClientSecretCredential  (explicit SPN login using
              AZURE_TENANT_ID + AZURE_CLIENT_ID + AZURE_CLIENT_SECRET)
  FALLBACK  → DefaultAzureCredential  (Managed Identity / Azure CLI)
              used automatically when SPN env vars are absent

Required .env vars for SPN login:
    AZURE_TENANT_ID       = xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
    AZURE_CLIENT_ID       = xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
    AZURE_CLIENT_SECRET   = <your-spn-client-secret>
    AZURE_KEYVAULT_URL    = https://your-vault-name.vault.azure.net/

Requirements:
    pip install azure-identity azure-keyvault-secrets
"""

import logging
import os
from typing import Optional

log = logging.getLogger(__name__)

# ── Azure SDK imports ──────────────────────────────────────────────────────────
try:
    from azure.identity import ClientSecretCredential, DefaultAzureCredential
    from azure.keyvault.secrets import SecretClient
    from azure.core.exceptions import ResourceNotFoundError, HttpResponseError
    _AZURE_SDK_AVAILABLE = True
except ImportError:
    _AZURE_SDK_AVAILABLE = False


class KeyVaultClient:
    """
    Wraps azure-keyvault-secrets with SPN authentication.

    Authentication order:
      1. ClientSecretCredential  — when all 3 SPN vars are present in env
      2. DefaultAzureCredential  — fallback (Managed Identity / CLI / Workload)

    Secrets are cached in memory after first fetch — Key Vault is only
    called once per secret per process lifetime.
    """

    def __init__(self, vault_url: str):
        if not _AZURE_SDK_AVAILABLE:
            raise ImportError(
                "Azure SDK packages not installed.\n"
                "Run: pip install azure-identity azure-keyvault-secrets"
            )
        if not vault_url:
            raise ValueError(
                "AZURE_KEYVAULT_URL is not set.\n"
                "Example: https://your-vault-name.vault.azure.net/"
            )

        self._vault_url = vault_url.rstrip("/")
        credential      = self._build_credential()

        self._client = SecretClient(
            vault_url=self._vault_url,
            credential=credential,
        )
        self._cache: dict[str, str] = {}

    def _build_credential(self):
        """
        Builds the best available Azure credential.

        Uses ClientSecretCredential (SPN) when all three AAD env vars are
        present.  Falls back to DefaultAzureCredential (which covers
        Managed Identity, Azure CLI, Workload Identity) when any SPN var
        is missing — useful for running on Azure App Service / AKS.
        """
        tenant_id     = os.getenv("AZURE_TENANT_ID", "").strip()
        client_id     = os.getenv("AZURE_CLIENT_ID", "").strip()
        client_secret = os.getenv("AZURE_CLIENT_SECRET", "").strip()

        if tenant_id and client_id and client_secret:
            log.info(
                f"[KEY VAULT] Auth method : SPN (ClientSecretCredential)\n"
                f"[KEY VAULT] Tenant ID   : {tenant_id}\n"
                f"[KEY VAULT] Client ID   : {client_id}\n"
                f"[KEY VAULT] Vault URL   : {self._vault_url}"
            )
            return ClientSecretCredential(
                tenant_id=tenant_id,
                client_id=client_id,
                client_secret=client_secret,
            )

        log.warning(
            "[KEY VAULT] SPN env vars not fully set — "
            "falling back to DefaultAzureCredential "
            "(Managed Identity / Azure CLI)"
        )
        return DefaultAzureCredential()

    def get_secret(self, secret_name: str) -> str:
        """
        Fetches a secret from Key Vault by name.
        Cached after first call — vault is not called again for the same name.

        Raises RuntimeError with a clear message on any failure.
        """
        if not secret_name:
            raise ValueError("secret_name must not be empty")

        if secret_name in self._cache:
            log.debug(f"[KEY VAULT] Cache hit : '{secret_name}'")
            return self._cache[secret_name]

        log.info(f"[KEY VAULT] Fetching secret '{secret_name}' ...")
        try:
            secret = self._client.get_secret(secret_name)
            value  = secret.value or ""

            if not value:
                raise RuntimeError(
                    f"Secret '{secret_name}' found in Key Vault but its value is empty."
                )

            self._cache[secret_name] = value
            log.info(f"[KEY VAULT] Secret '{secret_name}' fetched OK.")
            return value

        except ResourceNotFoundError:
            raise RuntimeError(
                f"Secret '{secret_name}' not found in Key Vault: {self._vault_url}\n"
                f"Create it with:\n"
                f"  az keyvault secret set "
                f"--vault-name <vault> --name {secret_name} --value <value>"
            )
        except HttpResponseError as exc:
            raise RuntimeError(
                f"Key Vault HTTP error fetching '{secret_name}': {exc.message}\n"
                f"Verify the SPN has 'get' permission on the vault:\n"
                f"  az keyvault set-policy --name <vault> "
                f"--object-id <SPN_OBJECT_ID> --secret-permissions get list"
            )
        except Exception as exc:
            raise RuntimeError(
                f"Unexpected error fetching '{secret_name}' from Key Vault: {exc}"
            )


# ── Module-level singleton ─────────────────────────────────────────────────────
_kv_client: Optional[KeyVaultClient] = None


def init_keyvault() -> KeyVaultClient:
    """
    Initialise the Key Vault singleton. Call once at application startup.
    """
    global _kv_client
    vault_url  = os.getenv("AZURE_KEYVAULT_URL", "").strip()
    _kv_client = KeyVaultClient(vault_url)
    return _kv_client


def get_secret(secret_name: str) -> str:
    """
    Retrieve a secret. Requires init_keyvault() to have been called first.
    """
    if _kv_client is None:
        raise RuntimeError(
            "Key Vault client not initialised. "
            "Call azure_keyvault_helper.init_keyvault() at startup."
        )
    return _kv_client.get_secret(secret_name)
