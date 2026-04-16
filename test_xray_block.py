import requests
import time
import os
import urllib3
import sys
from typing import Tuple, Dict, Any, List, Optional

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ===========================
# CONFIGURATION
# ===========================
JFROG_URL = os.environ.get("JFROG_URL", "https://trial789.jfrog.io")
JFROG_USER = os.environ.get("JFROG_USER", "abdul.effendi@izeno.com")
JFROG_PASS = os.environ.get("JFROG_PASS", "JfR06!2026")

REMOTE_REPO = os.environ.get("REMOTE_REPO", "maven-central-remote")
LOCAL_REPO = os.environ.get("LOCAL_REPO", "maven-libs-local")
VIRTUAL_REPO = os.environ.get("VIRTUAL_REPO", "maven-virtual")

POLICY_NAME = os.environ.get("POLICY_NAME", "block-critical-policy")
WATCH_NAME = os.environ.get("WATCH_NAME", "maven-security-watch")

# Polling / timing
XRAY_POLL_TIMEOUT = int(os.environ.get("XRAY_POLL_TIMEOUT", "300"))   # seconds
XRAY_POLL_INTERVAL = int(os.environ.get("XRAY_POLL_INTERVAL", "10"))  # seconds
REQUEST_TIMEOUT = int(os.environ.get("REQUEST_TIMEOUT", "120"))       # seconds

ARTIFACTORY_API = f"{JFROG_URL}/artifactory/api"
XRAY_API = f"{JFROG_URL}/xray/api"

session = requests.Session()
session.auth = (JFROG_USER, JFROG_PASS)
session.verify = False
session.headers.update({"Content-Type": "application/json"})

results: List[Dict[str, Any]] = []


# ===========================
# HELPERS
# ===========================
def short_text(text: str, limit: int = 250) -> str:
    if not text:
        return ""
    text = text.replace("\n", " ").replace("\r", " ").strip()
    return text[:limit]


def api_get(url: str, **kwargs) -> requests.Response:
    kwargs.setdefault("timeout", REQUEST_TIMEOUT)
    return session.get(url, **kwargs)


def api_post(url: str, **kwargs) -> requests.Response:
    kwargs.setdefault("timeout", REQUEST_TIMEOUT)
    return session.post(url, **kwargs)


def log_test(test_id: str, name: str, expected: str, actual: str, passed: bool, details: str = ""):
    status = "✅ PASS" if passed else "❌ FAIL"
    results.append({
        "id": test_id,
        "name": name,
        "expected": expected,
        "actual": actual,
        "passed": passed,
        "details": details
    })

    print(f"\n{'=' * 70}")
    print(f"  {status} | {test_id}: {name}")
    print(f"  Expected: {expected}")
    print(f"  Actual:   {actual}")
    if details:
        print(f"  Details:  {details}")
    print(f"{'=' * 70}")


def build_remote_artifact_url(group: str, artifact: str, version: str, filename: Optional[str] = None) -> str:
    path = group.replace(".", "/")
    if not filename:
        filename = f"{artifact}-{version}.jar"
    return f"{JFROG_URL}/artifactory/{REMOTE_REPO}/{path}/{artifact}/{version}/{filename}"


def build_cache_path(group: str, artifact: str, version: str, filename: Optional[str] = None) -> str:
    path = group.replace(".", "/")
    if not filename:
        filename = f"{artifact}-{version}.jar"
    return f"{REMOTE_REPO}-cache/{path}/{artifact}/{version}/{filename}"


def download_artifact(url: str, stream: bool = True) -> Tuple[int, str, int]:
    """
    Returns: (status_code, response_text_preview, content_length)
    """
    try:
        resp = api_get(url, stream=stream)
        body_preview = ""
        content_length = 0

        if resp.status_code == 200:
            # Force content read so we know actual downloaded size
            content = resp.content
            content_length = len(content)
        else:
            try:
                body_preview = short_text(resp.text, 300)
            except Exception:
                body_preview = ""

        return resp.status_code, body_preview, content_length
    except Exception as e:
        return -1, str(e), 0


def get_policy() -> Tuple[bool, str]:
    try:
        resp = api_get(f"{XRAY_API}/v2/policies/{POLICY_NAME}")
        if resp.status_code != 200:
            return False, f"HTTP {resp.status_code}: {short_text(resp.text)}"

        data = resp.json()
        rules = data.get("rules", [])
        if not rules:
            return False, "Policy exists but contains no rules"

        lines = []
        has_block = False
        for rule in rules:
            actions = rule.get("actions", {})
            block_active = actions.get("block_download", {}).get("active", False)
            severity = rule.get("criteria", {}).get("min_severity", "?")
            name = rule.get("name", "?")
            lines.append(f"Rule={name}, Severity={severity}, Block={block_active}")
            if block_active:
                has_block = True

        return has_block, " | ".join(lines)
    except Exception as e:
        return False, str(e)


def get_watch() -> Tuple[bool, str]:
    try:
        resp = api_get(f"{XRAY_API}/v2/watches/{WATCH_NAME}")
        if resp.status_code != 200:
            return False, f"HTTP {resp.status_code}: {short_text(resp.text)}"

        data = resp.json()
        general_data = data.get("general_data", {})
        resources = data.get("project_resources", {}).get("resources", [])
        policies = data.get("assigned_policies", [])

        active = general_data.get("active", False)
        details = [
            f"Active={active}",
            f"Resources={len(resources)}",
            f"Policies={len(policies)}"
        ]

        for r in resources:
            details.append(f"Resource={r.get('name')} ({r.get('type')})")
        for p in policies:
            details.append(f"Policy={p.get('name')} ({p.get('type')})")

        passed = active and len(resources) > 0 and len(policies) > 0
        return passed, " | ".join(details)
    except Exception as e:
        return False, str(e)


def fetch_violations(min_severity: str = "High") -> Tuple[bool, Dict[str, Any], str]:
    """
    Returns:
      success, json_data, summary
    """
    payload = {
        "filters": {
            "watch_name": WATCH_NAME,
            "min_severity": min_severity
        },
        "pagination": {
            "order_by": "severity",
            "limit": 50,
            "offset": 0
        }
    }

    try:
        resp = api_post(f"{XRAY_API}/v1/violations", json=payload)
        if resp.status_code != 200:
            return False, {}, f"HTTP {resp.status_code}: {short_text(resp.text)}"

        data = resp.json()
        violations = data.get("violations", [])
        total = data.get("total_violations", 0)

        lines = [f"Total violations={total}"]
        for v in violations[:5]:
            lines.append(
                f"{v.get('cve', 'N/A')} | {v.get('severity', '?')} | {short_text(v.get('summary', ''), 80)}"
            )

        return True, data, " | ".join(lines)
    except Exception as e:
        return False, {}, str(e)


def wait_for_violations(min_severity: str = "High", timeout: int = XRAY_POLL_TIMEOUT, interval: int = XRAY_POLL_INTERVAL) -> Tuple[bool, str]:
    start = time.time()
    attempts = 0

    while time.time() - start < timeout:
        attempts += 1
        ok, data, summary = fetch_violations(min_severity=min_severity)
        if ok:
            total = data.get("total_violations", 0)
            violations = data.get("violations", [])
            if total > 0 or len(violations) > 0:
                return True, f"Violations detected after {attempts} checks | {summary}"

        print(f"   ⏳ Waiting for Xray violations... attempt={attempts}")
        time.sleep(interval)

    return False, f"No violations detected after {attempts} checks within {timeout}s"


def get_artifact_summary(cache_path: str) -> Tuple[bool, str, Dict[str, Any]]:
    payload = {"paths": [cache_path]}

    try:
        resp = api_post(f"{XRAY_API}/v1/summary/artifact", json=payload)
        if resp.status_code != 200:
            return False, f"HTTP {resp.status_code}: {short_text(resp.text)}", {}

        data = resp.json()
        artifacts = data.get("artifacts", [])
        errors = data.get("errors", [])

        if artifacts:
            art = artifacts[0]
            general = art.get("general", {})
            issues = art.get("issues", [])
            summary = (
                f"Artifact={general.get('name', '?')} | "
                f"Version={general.get('version', '?')} | "
                f"Issues={len(issues)}"
            )
            return True, summary, data

        if errors:
            return False, f"Summary not ready/errors: {short_text(str(errors), 300)}", data

        return False, "No artifact data returned", data
    except Exception as e:
        return False, str(e), {}


def warmup_and_verify_block(
    test_id: str,
    name: str,
    group: str,
    artifact: str,
    version: str,
    min_severity: str = "High",
    filename: Optional[str] = None
):
    """
    Strategy:
    1. First request: trigger cache + scan
    2. Wait for violations (or indexing window)
    3. Second request: should be blocked if policy enforcement works
    """
    print(f"\n🧪 {test_id}: {name}")

    url = build_remote_artifact_url(group, artifact, version, filename)
    cache_path = build_cache_path(group, artifact, version, filename)

    # First request (warm-up)
    first_code, first_body, first_size = download_artifact(url)
    print(f"   First request status: {first_code}")

    if first_code in [403, 409]:
        log_test(
            test_id,
            name,
            "BLOCKED after Xray policy evaluation",
            f"Already BLOCKED on first request ({first_code})",
            True,
            first_body or "Blocked immediately by Xray"
        )
        return

    if first_code != 200:
        log_test(
            test_id,
            name,
            "Initial request should succeed or later be blocked",
            f"HTTP {first_code}",
            False,
            first_body
        )
        return

    # Poll Xray summary and/or violations
    summary_ready = False
    summary_text = ""
    start = time.time()
    attempts = 0

    while time.time() - start < XRAY_POLL_TIMEOUT:
        attempts += 1

        summary_ok, summary_info, summary_data = get_artifact_summary(cache_path)
        if summary_ok:
            summary_ready = True
            summary_text = summary_info
            print(f"   ✅ Artifact summary ready after {attempts} checks: {summary_info}")
            break

        ok, data, vio_summary = fetch_violations(min_severity=min_severity)
        if ok:
            total = data.get("total_violations", 0)
            if total > 0:
                summary_text = f"Violations visible before summary ready | {vio_summary}"
                print(f"   ✅ Violations detected after {attempts} checks")
                break

        print(f"   ⏳ Waiting for Xray scan/indexing... attempt={attempts}")
        time.sleep(XRAY_POLL_INTERVAL)

    if not summary_ready and not summary_text:
        summary_text = f"No summary/violation data ready after {XRAY_POLL_TIMEOUT}s"

    # Second request (enforcement check)
    second_code, second_body, second_size = download_artifact(url)
    print(f"   Second request status: {second_code}")

    if second_code in [403, 409]:
        log_test(
            test_id,
            name,
            "BLOCKED on re-download after scan/indexing",
            f"BLOCKED ({second_code})",
            True,
            f"Warm-up download size={first_size} bytes | {summary_text}"
        )
    elif second_code == 200:
        log_test(
            test_id,
            name,
            "BLOCKED on re-download after scan/indexing",
            f"ALLOWED (200) | first={first_size} bytes, second={second_size} bytes",
            False,
            f"Artifact still allowed after polling window. {summary_text}"
        )
    else:
        log_test(
            test_id,
            name,
            "BLOCKED on re-download after scan/indexing",
            f"HTTP {second_code}",
            False,
            f"{second_body} | {summary_text}"
        )


# ===========================
# TEST CASES
# ===========================
def test_01_block_log4j():
    warmup_and_verify_block(
        test_id="TC-01",
        name="Block Download: log4j-core 2.14.1 (CVE-2021-44228 - CRITICAL)",
        group="org.apache.logging.log4j",
        artifact="log4j-core",
        version="2.14.1",
        min_severity="Critical"
    )


def test_02_block_commons_collections():
    warmup_and_verify_block(
        test_id="TC-02",
        name="Block Download: commons-collections 3.2.1 (Known High/Critical Vulns)",
        group="commons-collections",
        artifact="commons-collections",
        version="3.2.1",
        min_severity="High"
    )


def test_03_allow_gson():
    test_id = "TC-03"
    name = "Allow Download: gson 2.10.1 (CLEAN - no vulnerabilities)"

    print(f"\n🧪 {test_id}: {name}")

    url = build_remote_artifact_url("com.google.code.gson", "gson", "2.10.1")
    cache_path = build_cache_path("com.google.code.gson", "gson", "2.10.1")

    code, body, size = download_artifact(url)

    if code == 200:
        summary_ok, summary_info, _ = get_artifact_summary(cache_path)
        details = f"Downloaded {size} bytes"
        if summary_ok:
            details += f" | {summary_info}"
        else:
            details += " | Summary may not be indexed yet"

        log_test(
            test_id,
            name,
            "ALLOWED (200 - clean artifact passes scan)",
            f"ALLOWED ({code}) - {size} bytes downloaded",
            True,
            details
        )
    elif code in [403, 409]:
        log_test(
            test_id,
            name,
            "ALLOWED (200)",
            f"BLOCKED ({code})",
            False,
            body or "Unexpected block for clean artifact"
        )
    else:
        log_test(
            test_id,
            name,
            "ALLOWED (200)",
            f"HTTP {code}",
            False,
            body
        )


def test_04_block_jackson():
    warmup_and_verify_block(
        test_id="TC-04",
        name="Block Download: jackson-databind 2.9.8 (Multiple CVEs)",
        group="com.fasterxml.jackson.core",
        artifact="jackson-databind",
        version="2.9.8",
        min_severity="High"
    )


def test_05_allow_slf4j():
    test_id = "TC-05"
    name = "Allow Download: slf4j-api 2.0.9 (CLEAN)"

    print(f"\n🧪 {test_id}: {name}")

    url = build_remote_artifact_url("org.slf4j", "slf4j-api", "2.0.9")
    cache_path = build_cache_path("org.slf4j", "slf4j-api", "2.0.9")

    code, body, size = download_artifact(url)

    if code == 200:
        summary_ok, summary_info, _ = get_artifact_summary(cache_path)
        details = f"Downloaded {size} bytes"
        if summary_ok:
            details += f" | {summary_info}"
        else:
            details += " | Summary may not be indexed yet"

        log_test(
            test_id,
            name,
            "ALLOWED (200)",
            f"ALLOWED ({code}) - {size} bytes",
            True,
            details
        )
    elif code in [403, 409]:
        log_test(
            test_id,
            name,
            "ALLOWED (200)",
            f"BLOCKED ({code})",
            False,
            body or "Unexpected block for clean artifact"
        )
    else:
        log_test(
            test_id,
            name,
            "ALLOWED (200)",
            f"HTTP {code}",
            False,
            body
        )


def test_06_check_violations():
    test_id = "TC-06"
    name = "Xray Violations Found for Watch"

    print(f"\n🧪 {test_id}: {name}")

    ok, data, summary = fetch_violations(min_severity="High")
    if not ok:
        log_test(
            test_id,
            name,
            "Violations found",
            "Violation API call failed",
            False,
            summary
        )
        return

    total = data.get("total_violations", 0)
    violations = data.get("violations", [])

    if total > 0 or len(violations) > 0:
        log_test(
            test_id,
            name,
            "Violations found",
            f"{total} violations detected",
            True,
            summary
        )
    else:
        log_test(
            test_id,
            name,
            "Violations found",
            "No violations yet",
            False,
            "No Xray violations visible yet. This usually means scan/indexing has not finished or no vulnerable artifact matched watch scope."
        )


def test_07_verify_policy():
    test_id = "TC-07"
    name = "Security Policy Configuration Correct"

    print(f"\n🧪 {test_id}: {name}")

    passed, details = get_policy()
    log_test(
        test_id,
        name,
        "Policy has block_download enabled",
        f"Block download = {passed}",
        passed,
        details
    )


def test_08_verify_watch():
    test_id = "TC-08"
    name = "Watch Configuration Active"

    print(f"\n🧪 {test_id}: {name}")

    passed, details = get_watch()
    actual = details if details else "Unable to inspect watch"
    log_test(
        test_id,
        name,
        "Watch is active with repos and policy",
        actual,
        passed,
        details
    )


def test_09_artifact_summary():
    test_id = "TC-09"
    name = "Xray Artifact Summary (clean artifact scan verified)"

    print(f"\n🧪 {test_id}: {name}")

    cache_path = build_cache_path("com.google.code.gson", "gson", "2.10.1")
    ok, summary, data = get_artifact_summary(cache_path)

    if ok:
        log_test(
            test_id,
            name,
            "Artifact summary available",
            "Summary retrieved successfully",
            True,
            summary
        )
    else:
        log_test(
            test_id,
            name,
            "Artifact summary available",
            "Summary not ready",
            False,
            summary
        )


# ===========================
# REPORT
# ===========================
def print_report():
    print("\n\n" + "=" * 70)
    print("📊 TEST RESULTS SUMMARY")
    print("=" * 70)

    passed = sum(1 for r in results if r["passed"])
    failed = sum(1 for r in results if not r["passed"])
    total = len(results)
    pass_rate = (passed / total * 100) if total else 0

    print(f"\n  Total: {total} | ✅ Passed: {passed} | ❌ Failed: {failed}")
    print(f"  Pass Rate: {pass_rate:.0f}%\n")

    print(f"  {'ID':<8} {'Test Name':<55} {'Result':<10}")
    print(f"  {'-' * 8} {'-' * 55} {'-' * 10}")

    for r in results:
        status = "✅ PASS" if r["passed"] else "❌ FAIL"
        print(f"  {r['id']:<8} {r['name'][:55]:<55} {status}")

    print(f"\n{'=' * 70}")

    if failed > 0:
        print("\n⚠️  NOTES:")
        print("   - Vulnerable artifact tests may fail if Xray scan/indexing has not completed yet.")
        print("   - This revised script already waits and retries, but very slow environments may need longer timeout.")
        print(f"   - Current timeout: {XRAY_POLL_TIMEOUT}s, interval: {XRAY_POLL_INTERVAL}s")
        print("   - You can increase them with env vars: XRAY_POLL_TIMEOUT / XRAY_POLL_INTERVAL")

    block_tests = [r for r in results if r["id"] in {"TC-01", "TC-02", "TC-04"}]
    if block_tests and all(r["passed"] for r in block_tests):
        print("\n🎉 All vulnerable artifact block tests passed!")
        print("   Xray is successfully blocking vulnerable artifacts after scan/indexing.")

    if total > 0 and passed == total:
        print("\n🎉 ALL TESTS PASSED!")


# ===========================
# MAIN
# ===========================
def main():
    print("=" * 70)
    print("🧪 JFrog Xray - Test Cases: Block vs Allow Artifacts (Revised)")
    print("=" * 70)
    print(f"\n📍 JFrog URL: {JFROG_URL}")
    print(f"📦 Remote Repo: {REMOTE_REPO}")
    print(f"📦 Local Repo:  {LOCAL_REPO}")
    print(f"🧪 Virtual Repo: {VIRTUAL_REPO}")
    print(f"🛡️  Policy: {POLICY_NAME}")
    print(f"👁️  Watch: {WATCH_NAME}")
    print(f"⏱️  Poll Timeout: {XRAY_POLL_TIMEOUT}s | Interval: {XRAY_POLL_INTERVAL}s")

    # Connectivity test
    print(f"\n🔌 Testing connection...")
    try:
        resp = api_get(f"{ARTIFACTORY_API}/system/ping")
        if resp.status_code == 200:
            print("✅ Connected!")
        else:
            print(f"❌ Connection failed: {resp.status_code} | {short_text(resp.text)}")
            sys.exit(1)
    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)

    # PART 1
    print("\n\n📋 PART 1: Configuration Verification")
    print("─" * 40)
    test_07_verify_policy()
    test_08_verify_watch()

    # PART 2
    print("\n\n📋 PART 2: Clean Artifact Allow Tests")
    print("─" * 40)
    test_03_allow_gson()
    test_05_allow_slf4j()

    # PART 3
    print("\n\n📋 PART 3: Vulnerable Artifact Block Tests")
    print("─" * 40)
    print("\n⏳ These tests use warm-up + polling + re-download verification.")
    test_01_block_log4j()
    test_02_block_commons_collections()
    test_04_block_jackson()

    # PART 4
    print("\n\n📋 PART 4: Xray Scan / Violation Verification")
    print("─" * 40)
    test_09_artifact_summary()
    test_06_check_violations()

    # Final report
    print_report()


if __name__ == "__main__":
    main()