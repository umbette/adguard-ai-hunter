#!/usr/bin/env python3
"""
Sentinel - Automated CI Health & Actions Watchdog
Monitors GitHub Actions workflow runs, detects failures, inspects logs,
and alerts or prepares automatic remediation.
"""

import json
import subprocess
import sys
from typing import Dict, List, Optional

REPO = "umbette/sentinel"

def get_recent_runs(limit: int = 10) -> List[Dict]:
    cmd = [
        "gh", "run", "list",
        "--repo", REPO,
        "--limit", str(limit),
        "--json", "databaseId,name,workflowName,headBranch,headSha,event,status,conclusion,createdAt,url"
    ]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return json.loads(res.stdout)
    except Exception as e:
        print(f"[ERROR] Failed to fetch GitHub Actions runs: {e}", file=sys.stderr)
        return []

def get_failed_logs(run_id: int) -> str:
    cmd = ["gh", "run", "view", str(run_id), "--repo", REPO, "--log-failed"]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True)
        return res.stdout
    except Exception:
        return ""

def audit_ci_health() -> Dict:
    runs = get_recent_runs(10)
    failed_runs = [r for r in runs if r.get("conclusion") == "failure"]
    in_progress = [r for r in runs if r.get("status") in ("in_progress", "queued")]
    success_runs = [r for r in runs if r.get("conclusion") == "success"]

    report = {
        "repo": REPO,
        "total_checked": len(runs),
        "success_count": len(success_runs),
        "in_progress_count": len(in_progress),
        "failed_count": len(failed_runs),
        "healthy": len(failed_runs) == 0,
        "failures": []
    }

    for f in failed_runs:
        run_id = f["databaseId"]
        logs = get_failed_logs(run_id)
        # Extract last 10 lines of failed log
        log_snippet = "\n".join(logs.strip().split("\n")[-12:]) if logs else "No logs"
        report["failures"].append({
            "id": run_id,
            "workflow": f.get("workflowName"),
            "event": f.get("event"),
            "commit": f.get("headSha", "")[:7],
            "url": f.get("url"),
            "log_snippet": log_snippet
        })

    return report

def main():
    report = audit_ci_health()
    if report["healthy"]:
        print(f"✅ [Sentinel CI Watchdog] All {report['total_checked']} recent workflow runs are healthy!")
        sys.exit(0)
    else:
        print(f"🚨 [Sentinel CI Watchdog] Found {report['failed_count']} failing workflow runs on {REPO}:")
        for f in report["failures"]:
            print(f"\n❌ Run #{f['id']} - {f['workflow']} ({f['commit']})")
            print(f"   URL: {f['url']}")
            print(f"   Log snippet:\n{f['log_snippet']}\n")
        sys.exit(1)

if __name__ == "__main__":
    main()
