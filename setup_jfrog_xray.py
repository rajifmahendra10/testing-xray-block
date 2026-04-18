
import requests
import json
import time
import urllib3
import sys
import os
import datetime

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ===========================
# CONFIGURATION
# Reads from environment variables if set (Jenkins), else falls back to defaults
# ===========================
JFROG_URL = os.environ.get("JFROG_URL", "https://trial789.jfrog.io")
JFROG_USER = os.environ.get("JFROG_USER", "abdul.effendi@izeno.com")
JFROG_PASS = os.environ.get("JFROG_PASS", "JfR06!2026")

# Repository names
REMOTE_REPO = "maven-central-remote"
LOCAL_REPO = "maven-libs-local"
VIRTUAL_REPO = "maven-virtual"

# Xray configuration
POLICY_NAME = "block-critical-policy"
WATCH_NAME = "maven-security-watch"

# Recipients for watch notifications
# Example:
# export WATCH_RECIPIENTS="abdul.effendi@izeno.com,security-team@izeno.com"
WATCH_RECIPIENTS = [
    x.strip()
    for x in os.environ.get("WATCH_RECIPIENTS", "abdul.effendi@izeno.com").split(",")
    if x.strip()
]

# How far back to apply existing content
APPLY_EXISTING_DAYS_BACK = int(os.environ.get("APPLY_EXISTING_DAYS_BACK", "30"))

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
        log("✅", success_msg)
        return True
    elif response.status_code == 204:
        log("✅", success_msg)
        return True
    elif response.status_code == 409:
        log("⚠️", f"Already exists - skipping ({response.status_code})")
        return True
    elif response.status_code == 400 and "already exists" in response.text.lower():
        log("⚠️", "Already exists - skipping")
        return True
    else:
        log("❌", fail_msg)
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
        "xrayIndex": True,
        "blockMismatchingMimeTypes": True,
        "contentSynchronisation": {
            "enabled": False
        }
    }

    resp = session.put(f"{ARTIFACTORY_API}/repositories/{REMOTE_REPO}", json=payload)
    if resp.status_code in [200, 201]:
        log("✅", f"Remote repo '{REMOTE_REPO}' created! (proxying Maven Central)")
        return True
    elif resp.status_code == 409 or (resp.status_code == 400 and "already exists" in resp.text.lower()):
        log("⚠️", "Already exists - enabling xrayIndex on existing repo...")
        upd = session.post(f"{ARTIFACTORY_API}/repositories/{REMOTE_REPO}", json={"xrayIndex": True})
        if upd.status_code in [200, 201]:
            log("✅", f"xrayIndex=True applied to '{REMOTE_REPO}'")
        else:
            log("⚠️", f"xrayIndex update: {upd.status_code} - {upd.text[:120]}")
        return True
    else:
        log("❌", "Failed to create remote repo")
        print(f"   Status: {resp.status_code}")
        print(f"   Response: {resp.text[:500]}")
        return False


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
    if resp.status_code in [200, 201]:
        log("✅", f"Local repo '{LOCAL_REPO}' created!")
        return True
    elif resp.status_code == 409 or (resp.status_code == 400 and "already exists" in resp.text.lower()):
        log("⚠️", "Already exists - enabling xrayIndex on existing repo...")
        upd = session.post(f"{ARTIFACTORY_API}/repositories/{LOCAL_REPO}", json={"xrayIndex": True})
        if upd.status_code in [200, 201]:
            log("✅", f"xrayIndex=True applied to '{LOCAL_REPO}'")
        else:
            log("⚠️", f"xrayIndex update: {upd.status_code} - {upd.text[:120]}")
        return True
    else:
        log("❌", "Failed to create local repo")
        print(f"   Status: {resp.status_code}")
        print(f"   Response: {resp.text[:500]}")
        return False


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
    return log_result(
        resp,
        f"Virtual repo '{VIRTUAL_REPO}' created!",
        "Failed to create virtual repo"
    )


# ===========================
# STEP 4: Enable Xray Indexing
# ===========================
def enable_xray_indexing():
    log("🔍", "STEP 4: Enabling Xray indexing on repositories...")

    bin_mgr_id = "default"
    try:
        bm_resp = session.get(f"{XRAY_API}/v1/binMgr")
        if bm_resp.status_code == 200:
            bm_data = bm_resp.json()
            if isinstance(bm_data, list) and len(bm_data) > 0:
                bin_mgr_id = bm_data[0].get("id", "default")
            elif isinstance(bm_data, dict):
                bin_mgr_id = bm_data.get("id", bm_data.get("bin_mgr_id", "default"))
        log("ℹ️", f"Binary Manager ID: {bin_mgr_id}")
    except Exception as e:
        log("⚠️", f"Could not get binary manager: {e}")

    current_indexed = []
    get_resp = session.get(f"{XRAY_API}/v1/binMgr/{bin_mgr_id}/repos")
    if get_resp.status_code == 200:
        try:
            data = get_resp.json()
            current_indexed = data.get("indexed_repos", [])
            log("ℹ️", f"Currently indexed: {[r.get('name', '?') for r in current_indexed]}")
        except Exception:
            log("⚠️", f"Could not parse indexed repos: {get_resp.text[:120]}")
    else:
        log("⚠️", f"GET indexed repos: {get_resp.status_code} - {get_resp.text[:120]}")

    indexed_names = [r.get("name", "") for r in current_indexed]
    new_repos = []

    for repo_name, repo_type in [
        (REMOTE_REPO, "remote"),
        (LOCAL_REPO, "local"),
        (f"{REMOTE_REPO}-cache", "local"),
    ]:
        if repo_name not in indexed_names:
            new_repos.append({"name": repo_name, "type": repo_type, "pkg_type": "Maven"})
            log("🔎", f"Adding '{repo_name}' to Xray index scope...")
        else:
            log("ℹ️", f"'{repo_name}' already in Xray index")

    if new_repos:
        all_repos = current_indexed + new_repos
        put_resp = session.put(
            f"{XRAY_API}/v1/binMgr/{bin_mgr_id}/repos",
            json={
                "indexed_repos": all_repos,
                "non_indexed_repos": []
            }
        )
        if put_resp.status_code in [200, 201, 204]:
            log("✅", f"Xray index scope updated via PUT /binMgr/{bin_mgr_id}/repos!")
        else:
            log("⚠️", f"PUT /binMgr/{bin_mgr_id}/repos: {put_resp.status_code} - {put_resp.text[:200]}")
            log("ℹ️", "Fallback: enabling xrayIndex via Artifactory API...")
            for repo_name in [REMOTE_REPO, LOCAL_REPO]:
                upd = session.post(
                    f"{ARTIFACTORY_API}/repositories/{repo_name}",
                    json={"xrayIndex": True}
                )
                if upd.status_code in [200, 201]:
                    log("✅", f"xrayIndex enabled: '{repo_name}' (Artifactory API)")
                else:
                    log("⚠️", f"xrayIndex '{repo_name}': {upd.status_code} - {upd.text[:80]}")
    else:
        log("✅", "All repos already in Xray index scope!")

    return True


# ===========================
# STEP 5: Create Security Policy
# ===========================
def create_security_policy():
    log("🛡️", f"STEP 5: Creating Security Policy '{POLICY_NAME}'...")
    log("🚫", "Policy: Block download jika severity >= Critical/High")

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
                        "unscanned": False,
                        "active": True
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
                        "active": True
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

    resp = session.post(f"{XRAY_API}/v2/policies", json=payload)

    if resp.status_code == 409 or (resp.status_code == 400 and "already exists" in resp.text.lower()):
        log("⚠️", "Policy already exists, updating...")
        resp = session.put(f"{XRAY_API}/v2/policies/{POLICY_NAME}", json=payload)

    return log_result(
        resp,
        f"Security Policy '{POLICY_NAME}' created/updated!\n"
        f"   → Rule 1: Block Critical vulnerabilities\n"
        f"   → Rule 2: Block High vulnerabilities\n"
        f"   → Notify watch recipients: ON",
        "Failed to create/update security policy"
    )


# ===========================
# STEP 6a: Apply Watch on Existing Content
# ===========================
def apply_watch_on_existing_content(days_back=30):
    log("🔄", f"STEP 6a: Applying watch '{WATCH_NAME}' on existing content...")

    end_date = datetime.datetime.utcnow().date()
    start_date = end_date - datetime.timedelta(days=days_back)

    payload = {
        "watch_names": [WATCH_NAME],
        "date_range": {
            "start_date": start_date.isoformat(),
            "end_date": end_date.isoformat()
        }
    }

    resp = session.post(f"{XRAY_API}/v1/applyWatch", json=payload)

    if resp.status_code in [200, 201, 202]:
        log("✅", f"Apply on existing content accepted for '{WATCH_NAME}'")
        log("ℹ️", f"Date range: {start_date.isoformat()} -> {end_date.isoformat()}")
        return True

    log("⚠️", f"Apply on existing content failed: HTTP {resp.status_code}")
    print(f"   Response: {resp.text[:500]}")
    return False


# ===========================
# STEP 6: Create / Update Watch
# ===========================
def create_watch():
    log("👁️", f"STEP 6: Creating Watch '{WATCH_NAME}'...")
    log("🔗", f"Watch = link antara Policy '{POLICY_NAME}' dan repos '{REMOTE_REPO}', '{LOCAL_REPO}'")

    bin_mgr_resp = session.get(f"{XRAY_API}/v1/binMgr")
    bin_mgr_id = "default"
    if bin_mgr_resp.status_code == 200:
        bin_data = bin_mgr_resp.json()
        if isinstance(bin_data, list) and len(bin_data) > 0:
            bin_mgr_id = bin_data[0].get("id", "default")
        elif isinstance(bin_data, dict):
            bin_mgr_id = bin_data.get("id", bin_data.get("bin_mgr_id", "default"))
        log("ℹ️", f"Binary Manager ID: {bin_mgr_id}")

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
        ],
        "watch_recipients": WATCH_RECIPIENTS
    }

    resp = session.post(f"{XRAY_API}/v2/watches", json=payload)

    if resp.status_code == 409 or (resp.status_code == 400 and "already exists" in resp.text.lower()):
        log("⚠️", "Watch already exists, updating...")
        resp = session.put(f"{XRAY_API}/v2/watches/{WATCH_NAME}", json=payload)

    ok = log_result(
        resp,
        f"Watch '{WATCH_NAME}' created/updated!\n"
        f"   → Monitoring: {REMOTE_REPO}, {LOCAL_REPO}\n"
        f"   → Policy: {POLICY_NAME}\n"
        f"   → Recipients: {', '.join(WATCH_RECIPIENTS)}",
        "Failed to create/update watch"
    )

    if ok:
        apply_watch_on_existing_content(APPLY_EXISTING_DAYS_BACK)

    return ok


# ===========================
# STEP 6b: Delete Cached Artifacts (Force Fresh Scan)
# ===========================
def delete_cached_artifacts():
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
            if resp.status_code in [200, 202, 204]:
                log("✅", f"Deleted from cache: {artifact_name}")
            elif resp.status_code == 404:
                log("ℹ️", f"Not in cache: {artifact_name}")
            else:
                log("⚠️", f"Delete {artifact_name}: HTTP {resp.status_code} - {resp.text[:120]}")
        except Exception as e:
            log("⚠️", f"Delete error: {e}")

    log("⏳", "Waiting 5 seconds for cache cleanup...")
    time.sleep(5)


# ===========================
# STEP 7: Pre-cache Artifacts (Trigger Xray Scan)
# ===========================
def precache_artifacts():
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
                log("✅", f"Cached: {name} ({size:,} bytes)")
            elif resp.status_code in [403, 409]:
                log("🛡️", f"Blocked already: {name} ({resp.status_code})")
            else:
                log("⚠️", f"{name}: HTTP {resp.status_code}")
        except Exception as e:
            log("❌", f"{name}: Error - {e}")

    log("✅", "All artifacts pre-cached! Xray will scan them during the wait period.")

    log("🔄", "Triggering Xray re-index on repositories...")
    for repo_name in [REMOTE_REPO, LOCAL_REPO]:
        try:
            resp = session.post(f"{XRAY_API}/v1/index", json={"repo_name": repo_name})
            if resp.status_code in [200, 201, 202]:
                log("✅", f"Re-index triggered for {repo_name}")
            else:
                log("⚠️", f"Re-index {repo_name}: HTTP {resp.status_code} - {resp.text[:100]}")
        except Exception as e:
            log("⚠️", f"Re-index {repo_name}: {e}")


# ===========================
# STEP 7c: Trigger explicit per-artifact Xray scan
# ===========================
def trigger_artifact_scans():
    log("🔬", "STEP 7c: Triggering per-artifact Xray scans...")

    components = [
        ("log4j-core 2.14.1", "gav://org.apache.logging.log4j:log4j-core:2.14.1"),
        ("commons-collections 3.2.1", "gav://commons-collections:commons-collections:3.2.1"),
        ("jackson-databind 2.9.8", "gav://com.fasterxml.jackson.core:jackson-databind:2.9.8"),
        ("gson 2.10.1", "gav://com.google.code.gson:gson:2.10.1"),
        ("slf4j-api 2.0.9", "gav://org.slf4j:slf4j-api:2.0.9"),
    ]

    for name, component_id in components:
        resp = session.post(f"{XRAY_API}/v1/scanArtifact", json={"componentID": component_id})
        if resp.status_code in [200, 201, 202]:
            log("✅", f"Scan triggered: {name} (HTTP {resp.status_code})")
        else:
            log("⚠️", f"{name}: {resp.status_code} - {resp.text[:120]}")

    for repo in [REMOTE_REPO, f"{REMOTE_REPO}-cache"]:
        try:
            resp = session.post(f"{XRAY_API}/v1/index", json={"repo_name": repo})
            log("ℹ️", f"Re-index {repo}: HTTP {resp.status_code}")
        except Exception as e:
            log("⚠️", f"Re-index {repo}: {e}")


# ===========================
# STEP 8: Verify Configuration
# ===========================
def verify_setup():
    log("🔍", "STEP 8: Verifying configuration...")

    print("\n--- Repositories ---")
    for repo in [REMOTE_REPO, LOCAL_REPO, VIRTUAL_REPO]:
        resp = session.get(f"{ARTIFACTORY_API}/repositories/{repo}")
        if resp.status_code == 200:
            data = resp.json()
            print(f"  ✅ {repo} ({data.get('rclass', '?')}) - packageType: {data.get('packageType', '?')}")
        else:
            print(f"  ❌ {repo} - NOT FOUND")

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
        print("  ❌ Policy not found")

    print("\n--- Xray Watch ---")
    resp = session.get(f"{XRAY_API}/v2/watches/{WATCH_NAME}")
    if resp.status_code == 200:
        data = resp.json()
        print(f"  ✅ Watch: {WATCH_NAME}")

        general_data = data.get("general_data", {})
        resources = data.get("project_resources", {}).get("resources", [])
        policies = data.get("assigned_policies", [])
        recipients = data.get("watch_recipients", [])

        print(f"     → Active: {general_data.get('active', False)}")
        print(f"     → Apply on existing content: {general_data.get('apply_on_existing_content', False)}")

        for r in resources:
            print(f"     → Monitoring: {r['name']} ({r['type']})")

        for p in policies:
            print(f"     → Policy: {p['name']} ({p['type']})")

        if recipients:
            for recipient in recipients:
                print(f"     → Recipient: {recipient}")
        else:
            print("     → Recipient: none")
    else:
        print("  ❌ Watch not found")


# ===========================
# MAIN
# ===========================
def main():
    print("=" * 70)
    print("🚀 JFrog Xray Setup: Block Vulnerable Artifacts BEFORE Entering Repo")
    print("=" * 70)
    print(f"\n📍 JFrog URL: {JFROG_URL}")
    print(f"👤 User: {JFROG_USER}")
    print(f"📧 Watch Recipients: {', '.join(WATCH_RECIPIENTS)}")
    print("\n🎯 Goal: Artifact dari internet di-SCAN dulu,")
    print("   CRITICAL/HIGH → BLOCK ❌")
    print("   CLEAN → ALLOW ✅")

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

    steps = [
        create_remote_repo,
        create_local_repo,
        create_virtual_repo,
        enable_xray_indexing,
        create_security_policy,
        create_watch,
        delete_cached_artifacts,
        precache_artifacts,
        trigger_artifact_scans,
    ]

    for step_fn in steps:
        ok = step_fn()
        if ok is False:
            log("❌", f"Stopping due to failure in step: {step_fn.__name__}")
            sys.exit(1)
        time.sleep(1)

    log("⏳", "Waiting 15 seconds for Xray to start scanning pre-cached artifacts...")
    time.sleep(15)

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
   │  │  CRITICAL/HIGH? → ❌ BLOCK                   │    │
   │  │  CLEAN?         → ✅ ALLOW                  │    │
   │  └──────────────────────────────────────────────┘    │
   │       ↓                                              │
   │  Virtual Repo: {VIRTUAL_REPO:<30}      │
   │       ↓                                              │
   │  Developer / CI/CD Pipeline                          │
   └──────────────────────────────────────────────────────┘

📧 Watch Recipients:
   {", ".join(WATCH_RECIPIENTS)}

🧪 Next Steps:
   1. Run test cases: python test_xray_block.py
   2. Try vulnerable build: mvn clean install -s settings-vulnerable.xml
   3. Try clean build: mvn clean install -s settings-clean.xml
""")

if __name__ == "__main__":
    main()