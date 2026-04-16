
import requests
import json
import time
import urllib3
import sys
import os


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ===========================
# CONFIGURATION
# Reads from environment variables if set (Jenkins), else falls back to defaults
# ===========================
JFROG_URL  = os.environ.get("JFROG_URL",  "https://trial789.jfrog.io")
JFROG_USER = os.environ.get("JFROG_USER", "abdul.effendi@izeno.com")
JFROG_PASS = os.environ.get("JFROG_PASS", "JfR06!2026")

# Repository names
REMOTE_REPO = "maven-central-remote"
LOCAL_REPO = "maven-libs-local"
VIRTUAL_REPO = "maven-virtual"

# Xray configuration
POLICY_NAME = "block-critical-policy"
WATCH_NAME = "maven-security-watch"

# API URLs
ARTIFACTORY_API = f"{JFROG_URL}/artifactory/api"
XRAY_API = f"{JFROG_URL}/xray/api"

# Session
session = requests.Session()
session.auth = (JFROG_USER, JFROG_PASS)
session.headers.update({"Content-Type": "application/json"})
session.verify = False


def log(emoji, message):
    print(f"\n{emoji} {message}")


def log_result(response, success_msg, fail_msg):
    if response.status_code in [200, 201]:
        log("✅", f"{success_msg}")
        return True
    elif response.status_code == 409:
        log("⚠️", f"Already exists - skipping ({response.status_code})")
        return True
    elif response.status_code == 400 and "already exists" in response.text.lower():
        log("⚠️", f"Already exists - skipping")
        return True
    else:
        log("❌", f"{fail_msg}")
        print(f"   Status: {response.status_code}")
        print(f"   Response: {response.text[:500]}")
        return False


# ===========================
# STEP 1: Create Remote Repository
# ===========================
def create_remote_repo():
    log("📦", f"STEP 1: Creating Remote Repository '{REMOTE_REPO}'...")
    log("📡", "This repo proxies Maven Central - artifacts from internet masuk sini dulu")

    payload = {
        "key": REMOTE_REPO,
        "rclass": "remote",
        "packageType": "maven",
        "url": "https://repo1.maven.org/maven2",
        "description": "Remote proxy to Maven Central - Xray scans artifacts here BEFORE caching",
        "repoLayoutRef": "maven-2-default",
        "handleReleases": True,
        "handleSnapshots": False,
        "suppressPomConsistencyChecks": True,
        "xrayIndex": True,               # Enable Xray indexing!
        "blockMismatchingMimeTypes": True,
        "contentSynchronisation": {
            "enabled": False
        }
    }

    resp = session.put(f"{ARTIFACTORY_API}/repositories/{REMOTE_REPO}", json=payload)
    return log_result(resp, 
                      f"Remote repo '{REMOTE_REPO}' created! (proxying Maven Central)",
                      f"Failed to create remote repo")


# ===========================
# STEP 2: Create Local Repository
# ===========================
def create_local_repo():
    log("📦", f"STEP 2: Creating Local Repository '{LOCAL_REPO}'...")
    log("💾", "Repo ini untuk artifact internal / verified artifacts")

    payload = {
        "key": LOCAL_REPO,
        "rclass": "local",
        "packageType": "maven",
        "description": "Local repo for verified/clean artifacts",
        "repoLayoutRef": "maven-2-default",
        "handleReleases": True,
        "handleSnapshots": True,
        "xrayIndex": True
    }

    resp = session.put(f"{ARTIFACTORY_API}/repositories/{LOCAL_REPO}", json=payload)
    return log_result(resp,
                      f"Local repo '{LOCAL_REPO}' created!",
                      f"Failed to create local repo")


# ===========================
# STEP 3: Create Virtual Repository
# ===========================
def create_virtual_repo():
    log("📦", f"STEP 3: Creating Virtual Repository '{VIRTUAL_REPO}'...")
    log("🔗", "Virtual repo = gabungan remote + local, developer pakai repo ini")

    payload = {
        "key": VIRTUAL_REPO,
        "rclass": "virtual",
        "packageType": "maven",
        "description": "Virtual repo aggregating remote + local - developers use this",
        "repoLayoutRef": "maven-2-default",
        "repositories": [LOCAL_REPO, REMOTE_REPO],
        "defaultDeploymentRepo": LOCAL_REPO,
        "artifactoryRequestsCanRetrieveRemoteArtifacts": True
    }

    resp = session.put(f"{ARTIFACTORY_API}/repositories/{VIRTUAL_REPO}", json=payload)
    return log_result(resp,
                      f"Virtual repo '{VIRTUAL_REPO}' created!",
                      f"Failed to create virtual repo")


# ===========================
# STEP 4: Enable Xray Indexing
# ===========================
def enable_xray_indexing():
    log("🔍", "STEP 4: Enabling Xray indexing on repositories...")

    # Add repos to Xray indexed resources
    payload = {
        "names": [REMOTE_REPO, LOCAL_REPO]
    }

    resp = session.put(f"{XRAY_API}/v1/binMgr/builds", json={
        "indexed_builds": []
    })

    # Index repositories in Xray
    for repo_name in [REMOTE_REPO, LOCAL_REPO]:
        payload = {
            "name": repo_name,
            "type": "local" if repo_name == LOCAL_REPO else "remote",
            "pkg_type": "Maven",
            "xray_index": True
        }
        log("🔎", f"  Enabling Xray index for '{repo_name}'...")

    # Use the v1 API to configure indexed repos
    resp = session.post(f"{XRAY_API}/v1/binMgr/repos", json={
        "indexed_repos": [
            {"name": REMOTE_REPO, "type": "remote", "pkg_type": "Maven"},
            {"name": LOCAL_REPO, "type": "local", "pkg_type": "Maven"}
        ]
    })

    if resp.status_code in [200, 201]:
        log("✅", "Xray indexing enabled for all repositories!")
        return True
    else:
        log("⚠️", f"Xray indexing response: {resp.status_code} - {resp.text[:300]}")
        log("ℹ️", "If repos were created with xrayIndex=true, indexing is already active")
        return True


# ===========================
# STEP 5: Create Security Policy 
# ===========================
def create_security_policy():
    log("🛡️", f"STEP 5: Creating Security Policy '{POLICY_NAME}'...")
    log("🚫", "Policy: Block download jika severity >= Critical")

    payload = {
        "name": POLICY_NAME,
        "description": "Block artifacts with Critical or High vulnerabilities before they enter the repository cache",
        "type": "security",
        "rules": [
            {
                "name": "block-critical-vulns",
                "priority": 1,
                "criteria": {
                    "min_severity": "Critical"
                },
                "actions": {
                    "webhooks": [],
                    "mails": [],
                    "block_download": {
                        "unscanned": False,   # Allow unscanned (first-time download OK)
                        "active": True         # Block download = ON for scanned vulns
                    },
                    "block_release_bundle_distribution": False,
                    "fail_build": True,
                    "notify_watch_recipients": True,
                    "notify_deployer": True,
                    "create_ticket_enabled": False
                }
            },
            {
                "name": "block-high-vulns",
                "priority": 2,
                "criteria": {
                    "min_severity": "High"
                },
                "actions": {
                    "webhooks": [],
                    "mails": [],
                    "block_download": {
                        "unscanned": False,
                        "active": True        # Also block High severity
                    },
                    "block_release_bundle_distribution": False,
                    "fail_build": True,
                    "notify_watch_recipients": True,
                    "notify_deployer": True,
                    "create_ticket_enabled": False
                }
            }
        ]
    }

    # Try to create, if exists try update
    resp = session.post(f"{XRAY_API}/v2/policies", json=payload)

    if resp.status_code == 409 or (resp.status_code == 400 and "already exists" in resp.text.lower()):
        log("⚠️", "Policy already exists, updating...")
        resp = session.put(f"{XRAY_API}/v2/policies/{POLICY_NAME}", json=payload)

    return log_result(resp,
                      f"Security Policy '{POLICY_NAME}' created!\n"
                      f"   → Rule 1: Block Critical vulnerabilities (block download)\n"
                      f"   → Rule 2: Block High vulnerabilities (block download)\n"
                      f"   → Unscanned artifacts: BLOCKED",
                      f"Failed to create security policy")


# ===========================
# STEP 6: Create Watch
# ===========================
def create_watch():
    log("👁️", f"STEP 6: Creating Watch '{WATCH_NAME}'...")
    log("🔗", f"Watch = link antara Policy '{POLICY_NAME}' dan Repo '{REMOTE_REPO}'")

    # First, get bin_mgr_id
    bin_mgr_resp = session.get(f"{XRAY_API}/v1/binMgr")
    bin_mgr_id = "default"
    if bin_mgr_resp.status_code == 200:
        bin_data = bin_mgr_resp.json()
        if isinstance(bin_data, list) and len(bin_data) > 0:
            bin_mgr_id = bin_data[0].get("id", "default")
        elif isinstance(bin_data, dict):
            managers = bin_data.get("bin_mgr_id", bin_data.get("binMgrId", "default"))
            if managers:
                bin_mgr_id = managers
        log("ℹ️", f"  Binary Manager ID: {bin_mgr_id}")

    payload = {
        "general_data": {
            "name": WATCH_NAME,
            "description": "Watch remote Maven repo - scan & block vulnerable artifacts from internet",
            "active": True,
            "apply_on_existing_content": True
        },
        "project_resources": {
            "resources": [
                {
                    "type": "repository",
                    "bin_mgr_id": bin_mgr_id,
                    "name": REMOTE_REPO,
                    "repo_type": "remote",
                    "filters": [
                        {
                            "type": "package-type",
                            "value": "Maven"
                        }
                    ]
                },
                {
                    "type": "repository",
                    "bin_mgr_id": bin_mgr_id,
                    "name": LOCAL_REPO,
                    "repo_type": "local",
                    "filters": [
                        {
                            "type": "package-type",
                            "value": "Maven"
                        }
                    ]
                }
            ]
        },
        "assigned_policies": [
            {
                "name": POLICY_NAME,
                "type": "security"
            }
        ]
    }

    resp = session.post(f"{XRAY_API}/v2/watches", json=payload)

    if resp.status_code == 409 or (resp.status_code == 400 and "already exists" in resp.text.lower()):
        log("⚠️", "Watch already exists, updating...")
        resp = session.put(f"{XRAY_API}/v2/watches/{WATCH_NAME}", json=payload)

    return log_result(resp,
                      f"Watch '{WATCH_NAME}' created!\n"
                      f"   → Monitoring: {REMOTE_REPO}, {LOCAL_REPO}\n"
                      f"   → Policy: {POLICY_NAME}\n"
                      f"   → Action: Block Critical & High on download",
                      f"Failed to create watch")


# ===========================
# STEP 6b: Delete Cached Artifacts (Force Fresh Scan)
# ===========================
def delete_cached_artifacts():
    """Delete cached vulnerable artifacts so Xray treats re-download as new scan event."""
    log("🗑️", "STEP 6b: Deleting cached vulnerable artifacts from remote cache...")
    log("ℹ️", "Forces Xray to re-scan when artifacts are re-downloaded")

    cache_repo = f"{REMOTE_REPO}-cache"
    paths = [
        "org/apache/logging/log4j/log4j-core/2.14.1/log4j-core-2.14.1.jar",
        "commons-collections/commons-collections/3.2.1/commons-collections-3.2.1.jar",
        "com/fasterxml/jackson/core/jackson-databind/2.9.8/jackson-databind-2.9.8.jar",
    ]

    for path in paths:
        artifact_name = path.split("/")[-1]
        url = f"{JFROG_URL}/artifactory/{cache_repo}/{path}"
        try:
            resp = session.delete(url)
            if resp.status_code in [200, 204]:
                log("✅", f"  Deleted from cache: {artifact_name}")
            elif resp.status_code == 404:
                log("ℹ️", f"  Not in cache: {artifact_name}")
            else:
                log("⚠️", f"  Delete {artifact_name}: HTTP {resp.status_code} - {resp.text[:100]}")
        except Exception as e:
            log("⚠️", f"  Delete error: {e}")

    log("⏳", "Waiting 5 seconds for cache cleanup...")
    time.sleep(5)


# ===========================
# STEP 7: Pre-cache Artifacts (Trigger Xray Scan)
# ===========================
def precache_artifacts():
    """Download test artifacts to trigger Xray scanning BEFORE tests run.
    This is critical: Xray only scans artifacts AFTER they are cached.
    Without this step, first download always passes (unscanned = allowed)."""
    log("📥", "STEP 7: Pre-caching test artifacts to trigger Xray scan...")
    log("ℹ️", "Xray akan scan artifact ini secara async setelah masuk cache")

    artifacts = [
        ("log4j-core-2.14.1 (CRITICAL)",
         f"{JFROG_URL}/artifactory/{REMOTE_REPO}/org/apache/logging/log4j/log4j-core/2.14.1/log4j-core-2.14.1.jar"),
        ("commons-collections-3.2.1 (HIGH)",
         f"{JFROG_URL}/artifactory/{REMOTE_REPO}/commons-collections/commons-collections/3.2.1/commons-collections-3.2.1.jar"),
        ("jackson-databind-2.9.8 (CRITICAL)",
         f"{JFROG_URL}/artifactory/{REMOTE_REPO}/com/fasterxml/jackson/core/jackson-databind/2.9.8/jackson-databind-2.9.8.jar"),
        ("gson-2.10.1 (CLEAN)",
         f"{JFROG_URL}/artifactory/{REMOTE_REPO}/com/google/code/gson/gson/2.10.1/gson-2.10.1.jar"),
        ("slf4j-api-2.0.9 (CLEAN)",
         f"{JFROG_URL}/artifactory/{REMOTE_REPO}/org/slf4j/slf4j-api/2.0.9/slf4j-api-2.0.9.jar"),
    ]

    for name, url in artifacts:
        try:
            resp = session.get(url, stream=True, timeout=60)
            size = len(resp.content) if resp.status_code == 200 else 0
            if resp.status_code == 200:
                log("✅", f"  Cached: {name} ({size:,} bytes)")
            else:
                log("⚠️", f"  {name}: HTTP {resp.status_code}")
        except Exception as e:
            log("❌", f"  {name}: Error - {e}")

    log("✅", "All artifacts pre-cached! Xray will scan them during the wait period.")

    # Force Xray to re-index the repos so scans apply on existing content
    log("🔄", "Triggering Xray re-index on repositories...")
    for repo_name in [REMOTE_REPO, LOCAL_REPO]:
        try:
            resp = session.post(
                f"{XRAY_API}/v1/index",
                json={"repo_name": repo_name}
            )
            if resp.status_code in [200, 201, 202]:
                log("✅", f"  Re-index triggered for {repo_name}")
            else:
                log("⚠️", f"  Re-index {repo_name}: HTTP {resp.status_code} - {resp.text[:100]}")
        except Exception as e:
            log("⚠️", f"  Re-index {repo_name}: {e}")


# ===========================
# STEP 8: Verify Configuration
# ===========================
def verify_setup():
    log("🔍", "STEP 7: Verifying configuration...")

    # Check repos
    print("\n--- Repositories ---")
    for repo in [REMOTE_REPO, LOCAL_REPO, VIRTUAL_REPO]:
        resp = session.get(f"{ARTIFACTORY_API}/repositories/{repo}")
        if resp.status_code == 200:
            data = resp.json()
            print(f"  ✅ {repo} ({data.get('rclass', '?')}) - packageType: {data.get('packageType', '?')}")
        else:
            print(f"  ❌ {repo} - NOT FOUND")

    # Check policy
    print("\n--- Xray Policy ---")
    resp = session.get(f"{XRAY_API}/v2/policies/{POLICY_NAME}")
    if resp.status_code == 200:
        data = resp.json()
        rules = data.get("rules", [])
        print(f"  ✅ Policy: {POLICY_NAME}")
        for rule in rules:
            severity = rule.get("criteria", {}).get("min_severity", "?")
            block = rule.get("actions", {}).get("block_download", {}).get("active", False)
            print(f"     → Rule: {rule['name']} | Min Severity: {severity} | Block Download: {block}")
    else:
        print(f"  ❌ Policy not found")

    # Check watch
    print("\n--- Xray Watch ---")
    resp = session.get(f"{XRAY_API}/v2/watches/{WATCH_NAME}")
    if resp.status_code == 200:
        data = resp.json()
        print(f"  ✅ Watch: {WATCH_NAME}")
        resources = data.get("project_resources", {}).get("resources", [])
        for r in resources:
            print(f"     → Monitoring: {r['name']} ({r['type']})")
        policies = data.get("assigned_policies", [])
        for p in policies:
            print(f"     → Policy: {p['name']} ({p['type']})")
    else:
        print(f"  ❌ Watch not found")


# ===========================
# MAIN
# ===========================
def main():
    print("=" * 70)
    print("🚀 JFrog Xray Setup: Block Vulnerable Artifacts BEFORE Entering Repo")
    print("=" * 70)
    print(f"\n📍 JFrog URL: {JFROG_URL}")
    print(f"👤 User: {JFROG_USER}")
    print(f"\n🎯 Goal: Artifact dari internet di-SCAN dulu,")
    print(f"   CRITICAL/HIGH → BLOCK ❌")
    print(f"   CLEAN → ALLOW ✅")

    # Test connection first
    log("🔌", "Testing connection to JFrog...")
    try:
        resp = session.get(f"{ARTIFACTORY_API}/system/ping")
        if resp.status_code == 200:
            log("✅", "Connected to JFrog successfully!")
        else:
            log("❌", f"Connection failed: {resp.status_code}")
            sys.exit(1)
    except Exception as e:
        log("❌", f"Connection error: {e}")
        sys.exit(1)

    # Execute all steps
    steps = [
        create_remote_repo,
        create_local_repo,
        create_virtual_repo,
        enable_xray_indexing,
        create_security_policy,
        create_watch,
        delete_cached_artifacts,
        precache_artifacts,
    ]

    for step_fn in steps:
        step_fn()
        time.sleep(1)  # Small delay between API calls

    # Wait for Xray to process scans
    log("⏳", "Waiting 15 seconds for Xray to start scanning pre-cached artifacts...")
    time.sleep(15)

    # Verify
    verify_setup()

    print("\n" + "=" * 70)
    print("🎉 SETUP COMPLETE!")
    print("=" * 70)
    print(f"""
📋 Summary:
   ┌──────────────────────────────────────────────────────┐
   │  Internet (Maven Central)                            │
   │       ↓                                              │
   │  Remote Repo: {REMOTE_REPO:<30}      │
   │       ↓                                              │
   │  🔍 Xray Scan (Watch: {WATCH_NAME:<20})     │
   │       ↓                                              │
   │  ┌─── Policy: {POLICY_NAME:<30} ───┐  │
   │  │                                              │    │
   │  │  CRITICAL/HIGH? → ❌ BLOCK (tidak masuk)    │    │
   │  │  CLEAN?         → ✅ ALLOW (masuk ke cache) │    │
   │  │                                              │    │
   │  └──────────────────────────────────────────────┘    │
   │       ↓ (if clean)                                   │
   │  Virtual Repo: {VIRTUAL_REPO:<30}      │
   │       ↓                                              │
   │  Developer / CI/CD Pipeline                          │
   └──────────────────────────────────────────────────────┘

🧪 Next Steps:
   1. Run test cases: python test_xray_block.py
   2. Try vulnerable build: mvn clean install -s settings-vulnerable.xml
   3. Try clean build: mvn clean install -s settings-clean.xml
   
🌐 Check in UI:
   {JFROG_URL}/ui/admin/xray/watches-new
   {JFROG_URL}/ui/admin/xray/policies-new
""")


if __name__ == "__main__":
    main()
