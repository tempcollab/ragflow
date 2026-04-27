# RAGFlow Security Audit Report

**Target:** RAGFlow v0.18.0 (open-source RAG engine)
**Repository:** https://github.com/infiniflow/ragflow
**Audit Date:** 2026-04-27
**Classification:** Confidential

---

## Executive Summary

This report presents the findings of a source-level and dynamic security audit of the RAGFlow codebase. Five independent, critical-to-high severity vulnerabilities were identified, each confirmed with a working proof-of-concept exploit script. The vulnerabilities span authentication, serialization, and access control — multiple attack paths lead to remote code execution (RCE) without elevated privilege.

The most severe findings are three distinct RCE vectors (findings 2, 4, and a component of finding 1) that can be triggered by any attacker who obtains write access to the MySQL database, which itself uses default credentials committed to the repository.

---

## Methodology

1. Static source code analysis of Python backend (`api/`, `common/`)
2. Identification of high-risk patterns: unsafe deserialization, cryptographic misuse, missing authentication decorators, dynamic code instantiation
3. Development of self-contained PoC scripts exercising the exact code paths
4. Dynamic confirmation against isolated Docker environment (exploits 1–4 require no running services; exploit 5 requires the RAGFlow API server)

---

## Findings Summary

| # | Title | Severity | Confirmed | PoC Script |
|---|-------|----------|-----------|------------|
| 1 | Committed RSA Private Key with Hardcoded Passphrase | **CRITICAL** | Yes | `01_rsa_key_compromise.py` |
| 2 | Unsafe Pickle Deserialization (RCE) | **CRITICAL** | Yes | `02_pickle_deserialization_rce.py` |
| 3 | JWT Tokens Never Expire | **HIGH** | Yes | `03_jwt_no_expiry.py` |
| 4 | Arbitrary Class Instantiation via JSON Hook (RCE) | **HIGH** | Yes | `04_from_dict_hook_rce.py` |
| 5 | Unauthenticated Document Image Retrieval | **HIGH** | Yes | `05_unauth_document_image.py` |

---

## Detailed Findings

---

### Finding 1: Committed RSA Private Key with Hardcoded Passphrase

**Severity:** CRITICAL (CVSS 9.1 — AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N)

**Affected Component:** `api/utils/crypt.py`

**Affected Files and Lines:**
- `conf/private.pem` — encrypted RSA private key committed to VCS
- `conf/public.pem` — RSA public key committed to VCS
- `api/utils/crypt.py:31` — `RSA.importKey(..., "Welcome")` (public key)
- `api/utils/crypt.py:40` — `RSA.importKey(..., "Welcome")` (private key)

**Description:**

The RSA key pair used to protect login passwords is committed directly to the Git repository. The private key is protected by the hardcoded passphrase `"Welcome"`, which appears in plaintext in `crypt.py`. Both the passphrase and the key material are therefore available to any party with repository read access.

The `crypt()` function encrypts login passwords (base64-encodes the password, RSA-encrypts with the public key, base64-encodes the ciphertext). The `decrypt()` function reverses this. Because both keys and the passphrase are public knowledge, this provides no confidentiality.

**Attack Scenario:**

1. Attacker clones or reads the repository (or accesses any copy of it).
2. Attacker intercepts or reads a login request (from logs, network capture, or database).
3. Using the committed `conf/private.pem` and passphrase `"Welcome"`, attacker decrypts the intercepted ciphertext and recovers the plaintext password.
4. Attacker uses recovered credentials to log in as the victim.

**PoC:** `autofyn_audit/exploits/01_rsa_key_compromise.py`
```
python autofyn_audit/exploits/01_rsa_key_compromise.py
```
Expected output: `RESULT: CONFIRMED`

**Remediation:**

1. Immediately rotate the RSA key pair — generate new keys with a strong randomly generated passphrase stored in a secrets manager (not the repository).
2. Remove `conf/private.pem` and `conf/public.pem` from the repository and from all Git history (use `git filter-repo` or BFG Repo Cleaner).
3. Store the passphrase as an environment variable or mounted secret, never in source code.
4. Consider replacing RSA-encrypted password transport with TLS (the canonical solution — transport-layer encryption makes application-level password encryption redundant).

---

### Finding 2: Unsafe Pickle Deserialization (RCE)

**Severity:** CRITICAL (CVSS 9.8 — AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Affected Component:** `api/utils/configs.py`, `api/db/db_models.py`

**Affected Files and Lines:**
- `api/utils/configs.py:53-61` — `deserialize_b64()` calls `pickle.loads()` unconditionally
- `api/utils/configs.py:57-59` — safe path guarded by `use_deserialize_safe_module` (default: `False`)
- `api/db/db_models.py:116-118` — `SerializedField.python_value()` calls `deserialize_b64()`

**Description:**

`deserialize_b64()` deserializes data from LONGTEXT database columns using `pickle.loads()`. A `RestrictedUnpickler` exists but is disabled: the guard condition `get_base_config('use_deserialize_safe_module', False)` defaults to `False` and the configuration key is set nowhere in the codebase. `pickle.loads()` on attacker-controlled data is a well-known, trivially exploitable RCE vector.

The MySQL database uses default credentials `root/infini_rag_flow` (committed in `docker/.env`), making write access to any table trivially achievable from the network.

**Attack Scenario:**

1. Attacker connects to MySQL using default credentials `root/infini_rag_flow`.
2. Attacker base64-encodes a malicious pickle payload (e.g., `__reduce__` calling `os.system`).
3. Attacker writes the payload to any `LONGTEXT` column that maps to a `SerializedField`.
4. The next ORM read of that row calls `SerializedField.python_value()` → `deserialize_b64()` → `pickle.loads()`, executing arbitrary code with the privileges of the RAGFlow server process.

**PoC:** `autofyn_audit/exploits/02_pickle_deserialization_rce.py`
```
python autofyn_audit/exploits/02_pickle_deserialization_rce.py
```
Expected output: `RESULT: CONFIRMED`, proof file created at `/tmp/pickle_rce_proof.txt`

**Remediation:**

1. Enable `use_deserialize_safe_module = true` in `service_conf.yaml` and set it as the default to `True`.
2. Expand `safe_module` in `RestrictedUnpickler` to include all modules that legitimately store pickled data.
3. Long-term: migrate serialized columns from pickle to JSON with a schema-validated deserializer (pickle is fundamentally unsafe for untrusted data).
4. Rotate MySQL credentials immediately; remove default credentials from all committed files.

---

### Finding 3: JWT Tokens Never Expire

**Severity:** HIGH (CVSS 7.5 — AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)

**Affected Component:** `api/apps/__init__.py`, `api/db/db_models.py`

**Affected Files and Lines:**
- `api/db/db_models.py:729-730` — `Serializer(...)` then `jwt.dumps(str(self.access_token))` — no expiry parameter
- `api/apps/__init__.py:114` — `jwt.loads(auth_token)` — no `max_age` parameter

**Description:**

RAGFlow uses `itsdangerous.URLSafeTimedSerializer` for session tokens. This serializer embeds a Unix timestamp in every token, and the `loads()` method accepts a `max_age` parameter to reject tokens older than a given number of seconds. However, RAGFlow's `_load_user()` calls `loads()` without `max_age`, meaning every token is accepted regardless of age.

A token created at account creation time remains valid indefinitely. There is no server-side expiry, no token rotation, and no revocation mechanism for individual tokens.

**Attack Scenario:**

1. Attacker obtains a RAGFlow authentication token (from a log file, network capture, compromised client, or social engineering).
2. Attacker uses the token to authenticate as the victim one week, one month, or one year later.
3. The token is accepted — there is no time-based rejection and no way for the victim to invalidate only that token without changing their password.

**PoC:** `autofyn_audit/exploits/03_jwt_no_expiry.py`
```
python autofyn_audit/exploits/03_jwt_no_expiry.py
```
Expected output: `RESULT: CONFIRMED` — token rejected with `max_age=1`, accepted without `max_age`.

**Remediation:**

1. Pass `max_age` to `jwt.loads()` in `_load_user()`:
   ```python
   access_token = str(jwt.loads(auth_token, max_age=TOKEN_MAX_AGE_SECONDS))
   ```
2. Choose a reasonable `TOKEN_MAX_AGE_SECONDS` (e.g., 86400 = 24 hours, or 604800 = 7 days).
3. Implement a token refresh endpoint so clients can renew tokens before expiry.
4. Optionally implement a token revocation list (store revoked token hashes in Redis) for explicit logout support.

---

### Finding 4: Arbitrary Class Instantiation via JSON Object Hook (RCE)

**Severity:** HIGH (CVSS 8.8 — AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H)

**Affected Component:** `api/utils/__init__.py`, `api/db/db_models.py`

**Affected Files and Lines:**
- `api/utils/__init__.py:19-27` — `from_dict_hook()` calls `importlib.import_module()` and `getattr(module, type)(**data)`
- `api/db/db_models.py:255-257` — `JsonSerializedField` uses `from_dict_hook` as default `object_hook`

**Description:**

`from_dict_hook()` is registered as the `object_hook` for `json.loads()` in `JsonSerializedField`. When deserializing, it inspects every JSON object for `"module"`, `"type"`, and `"data"` keys. If present, it imports the named module and instantiates the named class with `**data`. This allows arbitrary Python class instantiation from database-stored JSON.

An attacker who can write to any `JsonSerializedField` column can trigger instantiation of `subprocess.Popen`, `os.system`, or any other callable — achieving RCE when the row is next read.

**Attack Scenario:**

1. Attacker connects to MySQL using default credentials.
2. Attacker writes the following JSON to a `JsonSerializedField` column:
   ```json
   {"module": "subprocess", "type": "Popen", "data": {"args": ["attacker_binary"], "stdout": -1}}
   ```
3. When RAGFlow reads the row, `json.loads(..., object_hook=from_dict_hook)` instantiates `subprocess.Popen(args=["attacker_binary"], stdout=-1)`, executing arbitrary code.

**PoC:** `autofyn_audit/exploits/04_from_dict_hook_rce.py`
```
python autofyn_audit/exploits/04_from_dict_hook_rce.py
```
Expected output: `RESULT: CONFIRMED` — `subprocess.Popen` instantiated and `id` command output captured.

**Remediation:**

1. Remove `from_dict_hook` as a default `object_hook` from `JsonSerializedField`. Use it only for specific trusted internal serialization paths where the data origin is verified.
2. If type-preserving deserialization is required, implement a strict allowlist: enumerate the exact set of permitted module+type combinations, and reject anything not on the list.
3. Consider replacing this mechanism with a typed schema (e.g., Pydantic models) that does not involve dynamic class instantiation.

---

### Finding 5: Unauthenticated Document Image Retrieval

**Severity:** HIGH (CVSS 7.5 — AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)

**Affected Component:** `api/apps/restful_apis/document_api.py`

**Affected Files and Lines:**
- `api/apps/restful_apis/document_api.py:1633-1666` — `get_document_image()` — no `@login_required`
- `api/apps/restful_apis/document_api.py:57` — adjacent `upload_info()` — has `@login_required`

**Description:**

The endpoint `GET /api/v1/documents/images/<image_id>` serves document images from MinIO object storage. It has no `@login_required` decorator and performs no authentication or authorization check. The `image_id` parameter is parsed as `<bucket>-<object_name>` and passed directly to the MinIO storage backend.

Every other document endpoint in the same file (`upload_info`, `list_docs`, `update_document`, etc.) carries the `@login_required` decorator. This endpoint was likely missed during a code review.

**Attack Scenario:**

1. Attacker identifies the `/api/v1/documents/images/` endpoint (publicly documented API).
2. Attacker enumerates or guesses `<bucket>-<object_name>` pairs (bucket names correlate with tenant IDs; object names are document-derived UUIDs).
3. Attacker retrieves document images without any authentication, bypassing all access controls.
4. Sensitive document content (scanned contracts, invoices, personal data) is exposed to unauthenticated parties.

**PoC:** `autofyn_audit/exploits/05_unauth_document_image.py`
```
python autofyn_audit/exploits/05_unauth_document_image.py --url http://localhost:9380
```
Expected output: `RESULT: CONFIRMED` — protected endpoint returns 401; image endpoint returns non-401.

Static analysis (no server required):
```
python autofyn_audit/exploits/05_unauth_document_image.py
```
Expected output: `RESULT: CONFIRMED (static analysis)`

**Remediation:**

1. Add `@login_required` and `@add_tenant_id_to_kwargs` decorators to `get_document_image()`.
2. After authentication, verify that the requesting user's tenant owns the bucket referenced in `image_id`.
3. Audit all routes in `document_api.py` (and other API files) for missing authentication decorators — add a linter rule or decorator-enforcement test.

---

## Infrastructure Notes

Default credentials committed to the repository (`docker/.env`) enable direct database access:

| Service | Default Credentials |
|---------|---------------------|
| MySQL | `root` / `infini_rag_flow` |
| Redis | password: `infini_rag_flow` |
| MinIO | `rag_flow` / `infini_rag_flow` |
| Elasticsearch | `elastic` / `infini_rag_flow` |

These default credentials are referenced throughout the codebase and in Docker Compose configuration. Any deployment that does not override these values is trivially accessible from the network. Findings 2 and 4 require only MySQL write access, which these credentials provide.

**Recommendation:** Mandate credential rotation as part of the deployment process. Remove default credential values from committed configuration; use Docker secrets or environment variable injection instead.

---

## Reproduction Steps (Quick Reference)

```bash
# From repo root
cd /home/agentuser/repo   # or wherever the repo is cloned

# Exploits 1-4: no services needed
python autofyn_audit/exploits/01_rsa_key_compromise.py
python autofyn_audit/exploits/02_pickle_deserialization_rce.py
python autofyn_audit/exploits/03_jwt_no_expiry.py
python autofyn_audit/exploits/04_from_dict_hook_rce.py

# Exploit 5: optional server (static analysis confirms without server)
python autofyn_audit/exploits/05_unauth_document_image.py

# With live server:
bash autofyn_audit/setup.sh   # starts supporting services
# (start ragflow server separately — see setup.sh output)
python autofyn_audit/exploits/05_unauth_document_image.py --url http://localhost:9380
bash autofyn_audit/teardown.sh  # cleanup
```
