"""Hosted/paid surfaces (spec §2.1): explicit stubs, not fake functionality."""
from .errors import NotImplementedSurface

HOSTED = "https://github.com/LatticeAG/bedrock#hosted-registry"


def _hosted(name: str):
    raise NotImplementedSurface(f"{name} — hosted registry pilot surface. See {HOSTED}")


def provision_hosted_tenant():
    return _hosted("provisionHostedTenant")


def issue_managed_credential():
    return _hosted("issueManagedCredential")


def deploy_hosted_worker():
    return _hosted("deployHostedWorker")


def hosted_backup_custody():
    return _hosted("hostedBackupCustody")


def public_checkpoint_anchor():
    return _hosted("publicCheckpointAnchor")
