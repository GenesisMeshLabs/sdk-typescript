"""Generate cross-language test vectors from the Python reference.

Runs the Pilot 1 flow against an in-process Network Authority (evidence store
on, policy enforcement required) and writes every artifact the TypeScript SDK
must reproduce byte-for-byte and verify: an attestation with non-ASCII claims,
a signed policy, allowed and denied decisions with their bindings and proofs,
execution evidence on a resource chain, a retention checkpoint, and the full
gm.evidence.event export.

    <genesismesh>/.venv/bin/python scripts/generate_vectors.py
"""

from __future__ import annotations

import json
import sys
import tempfile
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import nacl.encoding
import nacl.signing

from genesis_mesh.crypto import generate_keypair, sign_data, sign_model
from genesis_mesh.models import GenesisBlock, NetworkAuthority, PolicyManifestRef
from genesis_mesh.models.context import BoundaryDecision
from genesis_mesh.models.evidence_store import ResourceHead, RetentionCheckpoint
from genesis_mesh.na_service.server import NetworkAuthorityService
from genesis_mesh.trust.evidence_store import sign_retention_checkpoint
from genesis_mesh.trust.execution import record_execution

OUT = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "python-vectors.json"
VENDOR = "vendor-zoë"
SECRET = "kv:pilot-vault/vendor-zoë-api"


def _headers(keypair, body: dict) -> dict:
    ts = datetime.now(timezone.utc).isoformat()
    nonce = str(uuid.uuid4())
    canonical = json.dumps(
        {"body": body, "key_id": "ops", "timestamp": ts, "nonce": nonce}, sort_keys=True, separators=(",", ":")
    )
    return {
        "X-Admin-Key-Id": "ops",
        "X-Admin-Timestamp": ts,
        "X-Admin-Nonce": nonce,
        "X-Admin-Signature": sign_data(canonical.encode("utf-8"), keypair.private_key),
    }


def main() -> None:
    root = nacl.signing.SigningKey.generate()
    na_pub = root.verify_key.encode(encoder=nacl.encoding.Base64Encoder).decode()
    now = datetime.now(timezone.utc)
    genesis = GenesisBlock(
        network_name="vectors",
        network_version="v0.1",
        root_public_key=na_pub,
        network_authority=NetworkAuthority(public_key=na_pub, valid_from=now, valid_to=now + timedelta(days=3650)),
        policy_manifest=PolicyManifestRef(hash="sha256:test", url=None),
    )
    genesis.signatures.append(sign_model(genesis, root, "root"))
    operator = generate_keypair()

    with tempfile.TemporaryDirectory() as tmp:
        service = NetworkAuthorityService(
            genesis_block=genesis, na_private_key=root, key_id="na-vectors",
            db_path=str(Path(tmp) / "na.db"),
            operator_public_keys={"ops": operator.public_key_b64},
            operator_key_tiers={"ops": "privileged"},
            boundary_policy_enforcement="required",
            evidence_store="on",
        )
        service.app.config["TESTING"] = True
        client = service.app.test_client()

        def post(url: str, body: dict, expect: int) -> dict:
            resp = client.post(url, json=body, headers=_headers(operator, body))
            assert resp.status_code == expect, (url, resp.status_code, resp.get_json())
            return resp.get_json()

        def get(url: str):
            resp = client.get(url, headers=_headers(operator, {}))
            assert resp.status_code == 200, (url, resp.status_code)
            return resp

        attestation = post("/admin/attestations", {
            "subject_id": VENDOR, "roles": ["role:client"], "validity_hours": 87600,
            "claims": {"capabilities": ["sp-secret.create", "sp-secret.rotate", "sp-secret.revoke"],
                       "apps": ["app-zürich"], "risk_score": 0.25, "note": "😀"},
        }, 201)
        policy = post("/admin/boundary-policies", {
            "policy_id": "vendor-sp-secret",
            "description": "Vendor SP secrets - pilot 1",
            "valid_from": now.isoformat(),
            "valid_until": (now + timedelta(days=3650)).isoformat(),
            "selector": {"parent_kinds": ["attestation"], "capabilities": ["sp-secret.*"]},
            "gates": [
                {"gate_id": "app", "gate_type": "attestation_claim.v1", "order": 0,
                 "config": {"path": "request_parameters.app_id", "claim": "apps"}},
                {"gate_id": "owner", "gate_type": "required_parameter.v1", "order": 1, "mode": "observe",
                 "config": {"path": "attributes.owner"}},
                {"gate_id": "max-lifetime", "gate_type": "max_value.v1", "order": 2,
                 "config": {"path": "request_parameters.lifetime_days", "max": 90}},
            ],
        }, 201)
        post(f"/admin/boundary-policies/{policy['policy_id']}/activate", {"version": policy["version"]}, 200)

        controller = nacl.signing.SigningKey.generate()
        controller_pub = controller.verify_key.encode(encoder=nacl.encoding.Base64Encoder).decode()
        post("/admin/evidence/executor-keys", {
            "key_id": "ctrl", "public_key": controller_pub, "executor_sovereign_id": "secrets-controller",
        }, 201)

        def evaluate(capability: str, app: str, days: int) -> dict:
            return post("/admin/boundary/evaluate", {
                "attestation_id": attestation["attestation_id"], "requested_capability": capability,
                "context": {"request_parameters": {"app_id": app, "lifetime_days": days},
                            "attributes": {"secret_store": "azure-key-vault"}},
            }, 201)

        executions = []
        allowed = None
        prior = None
        for action in ("create", "rotate"):
            allowed = evaluate(f"sp-secret.{action}", "app-zürich", 30)
            decision = BoundaryDecision.model_validate(allowed["decision"])
            assert decision.authorized, decision.denial_reason
            record = record_execution(
                decision, "secrets-controller", f"sp-secret.{action}", "success", controller, issued_by="ctrl",
                execution_parameters={"secret_version": f"v{len(executions) + 1}", "owner": "Zoë"},
                resource_id=SECRET, resource_action=action, prior_resource_record=prior,
            )
            body = record.model_dump(mode="json")
            assert client.post("/evidence/execution", json={"evidence": body}).status_code == 201
            executions.append(body)
            prior = record

        denied = evaluate("sp-secret.create", "app-elsewhere", 365)
        assert not denied["decision"]["authorized"]

        checkpoint = sign_retention_checkpoint(RetentionCheckpoint(
            cutoff=now, removed_through_sequence=3, last_removed_entry_digest="0" * 64, removed_count=3,
            resource_heads={SECRET: ResourceHead(resource_sequence=1, record_digest="1" * 64)},
            issued_by="na-vectors",
        ), root, "na-vectors")

        export = get("/admin/evidence/export").get_data(as_text=True)
        vectors = {
            "generated_by": "genesismesh scripts via sdk-typescript/scripts/generate_vectors.py",
            "na_public_key": na_pub,
            "executor_keys": [{"key_id": "ctrl", "public_key": controller_pub,
                               "executor_sovereign_id": "secrets-controller"}],
            "resource_id": SECRET,
            "vendor_id": VENDOR,
            "attestation": attestation,
            "attestation_digest": __import__("genesis_mesh.models.sovereign", fromlist=["x"])
                .MembershipAttestation.model_validate(attestation).digest(),
            "policy": policy,
            "policy_digest": __import__("genesis_mesh.models.boundary_policy", fromlist=["x"])
                .BoundaryPolicy.model_validate(policy).digest(),
            "allowed": allowed,
            "denied": denied,
            "executions": executions,
            "execution_digests": [
                __import__("genesis_mesh.models.execution", fromlist=["x"]).ExecutionEvidence.model_validate(e).digest()
                for e in executions
            ],
            "checkpoint": checkpoint.model_dump(mode="json"),
            "export": export,
            "server_verification": get("/admin/evidence/verify").get_json(),
        }
    OUT.write_text(json.dumps(vectors, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"wrote {OUT}", file=sys.stderr)


if __name__ == "__main__":
    main()
