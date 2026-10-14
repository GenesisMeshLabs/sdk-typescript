"""Disposable loopback NA for SDK integration tests. Requires the Python core installed.

Only generated test credentials are emitted, to the parent test process. The
real HTTP routes, signatures, policy enforcement and SQLite store are used.

v1.6.0: the test may stop and start the server, keeping the NA and its store,
by writing ``stop`` or ``start`` on a line of this process's standard input;
each is answered with a JSON line once done (``{"control": "stopped"}``).
"""
import importlib.util
import inspect
import json
import signal
import sys
import tempfile
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

from werkzeug.serving import make_server
from genesis_mesh.crypto import generate_keypair, sign_model
from genesis_mesh.models import GenesisBlock, NetworkAuthority, PolicyManifestRef
from genesis_mesh.na_service.server import NetworkAuthorityService


def main():
    root = generate_keypair()
    operator = generate_keypair()
    # A second privileged operator key, of another holder: it decides reviews (1.4.0).
    reviewer = generate_keypair()
    now = datetime.now(timezone.utc)
    genesis = GenesisBlock(
        network_name="sdk-e2e", network_version="v0.1", root_public_key=root.public_key_b64,
        network_authority=NetworkAuthority(public_key=root.public_key_b64, valid_from=now, valid_to=now + timedelta(days=1)),
        policy_manifest=PolicyManifestRef(hash="sha256:test", url=None),
    )
    genesis.signatures.append(sign_model(genesis, root.private_key, "root"))
    # Changes outside the controlled path, on a core that has them (1.3.0).
    options = {}
    parameters = inspect.signature(NetworkAuthorityService.__init__).parameters
    if "evidence_out_of_band" in parameters:
        options["evidence_out_of_band"] = "on"
    # Remediation, reviews and emergency changes, on a core that has them (1.4.0;
    # EVIDENCE_REMEDIATION=on): each operator key has a named holder of its own.
    remediation = "evidence_remediation" in parameters
    keys = {"ops": operator.public_key_b64}
    tiers = {"ops": "privileged"}
    if remediation:
        options.update(evidence_remediation="on", operator_key_holders={"ops": "alice", "ops-2": "bob"})
        keys["ops-2"] = reviewer.public_key_b64
        tiers["ops-2"] = "privileged"
    # Pre-issued grants, on a core that has them (1.6.0; EVIDENCE_GRANTS=on).
    grants = "evidence_grants" in parameters and "evidence_out_of_band" in options
    if grants:
        options["evidence_grants"] = "on"
    with tempfile.TemporaryDirectory(prefix="gm-sdk-e2e-") as tmp:
        service = NetworkAuthorityService(
            genesis_block=genesis, na_private_key=root.private_key, key_id="na-e2e",
            db_path=str(Path(tmp) / "na.db"), operator_public_keys=keys,
            operator_key_tiers=tiers, boundary_policy_enforcement="required", evidence_store="on",
            **options,
        )
        # Do not spend a minute between pages in a local integration test.
        service.rate_limiter.allow = lambda *args, **kwargs: True
        server = make_server("127.0.0.1", 0, service.app)
        port = server.server_port
        signal.signal(signal.SIGTERM, lambda *_: exit(0))
        config = {"baseUrl": f"http://127.0.0.1:{port}",
                  "signingKeyBase64": operator.private_key_b64, "keyId": "ops",
                  "naPublicKey": root.public_key_b64, "outOfBand": "evidence_out_of_band" in options,
                  "remediation": remediation,
                  # 1.5.0: the key history, audit packs and archives; the root key signed the genesis block.
                  "audit": importlib.util.find_spec("genesis_mesh.trust.key_succession") is not None,
                  "rootPublicKey": root.public_key_b64,
                  # 1.6.0: pre-issued grants; the server stops and starts on request (see above).
                  "grants": grants, "control": True}
        if remediation:
            config["reviewer"] = {"keyId": "ops-2", "signingKeyBase64": reviewer.private_key_b64}
        serving = threading.Thread(target=server.serve_forever, daemon=True)
        serving.start()
        print(json.dumps(config), flush=True)
        try:
            for line in sys.stdin:
                command = line.strip()
                if command == "stop" and server is not None:
                    server.shutdown()
                    server.server_close()
                    server = None
                    print(json.dumps({"control": "stopped"}), flush=True)
                elif command == "start" and server is None:
                    server = make_server("127.0.0.1", port, service.app)
                    serving = threading.Thread(target=server.serve_forever, daemon=True)
                    serving.start()
                    print(json.dumps({"control": "started"}), flush=True)
            # The test closed standard input: serve until it stops this process.
            serving.join()
        finally:
            if server is not None:
                server.shutdown()
                server.server_close()


if __name__ == "__main__":
    main()
