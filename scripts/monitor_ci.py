#!/usr/bin/env python3
"""
Sentinel - Automated CI Health & Actions Watchdog
Monitors GitHub Actions workflow runs for HEAD on main, detects failures,
inspects error logs, and reports actionable status.
"""

import json
import subprocess
import sys
from typing import Dict, List, Optional

REPO = "umbette/sentinel"

def get_runs_by_workflow(branch: str = "main", limit: int = 20) -> Dict[str, Dict]:
    """
    Fetches recent workflow runs and groups by workflowName, keeping only the latest run for each.
    """
    cmd = [
        "gh", "run", "list",
        "--repo", REPO,
        "--branch", branch,
        "--limit", str(limit),
        "--json", "databaseId,name,workflowName,headBranch,headSha,event,status,conclusion,createdAt,url"
    ]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, check=True)
        runs = json.loads(res.stdout)
    except Exception as e:
        print(f"[ERROR] Failed to fetch GitHub Actions runs: {e}", file=sys.stderr)
        return {}

    latest_by_workflow = {}
    for r in runs:
        w_name = r.get("workflowName")
        if w_name and w_name not in latest_by_workflow:
            latest_by_workflow[w_name] = r
    return latest_by_workflow

def get_failed_logs(run_id: int) -> str:
    cmd = ["gh", "run", "view", str(run_id), "--repo", REPO, "--log-failed"]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True)
        return res.stdout
    except Exception:
        return ""

def audit_ci_health(branch: str = "main") -> Dict:
    latest_workflows = get_runs_by_workflow(branch=branch)
    failed_workflows = []
    in_progress = []
    healthy_workflows = []

    for w_name, run in latest_workflows.items():
        status = run.get("status")
        conclusion = run.get("conclusion")
        if status in ("in_progress", "queued"):
            in_progress.append(run)
        elif conclusion == "failure":
            failed_workflows.append(run)
        elif conclusion == "success":
            healthy_workflows.append(run)

    report = {
        "repo": REPO,
        "branch": branch,
        "total_active_workflows": len(latest_workflows),
        "success_count": len(healthy_workflows),
        "in_progress_count": len(in_progress),
        "failed_count": len(failed_workflows),
        "healthy": len(failed_workflows) == 0,
        "failures": []
    }

    for f in failed_workflows:
        run_id = f["databaseId"]
        logs = get_failed_logs(run_id)
        log_snippet = "\n".join(logs.strip().split("\n")[-15:]) if logs else "No logs"
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
        print(f"✅ [Sentinel CI Watchdog] All {report['total_active_workflows']} active workflows on branch '{report['branch']}' are HEALTHY & GREEN:")
        # List them
        runs = get_runs_by_workflow()
        for name, r in runs.items():
            print(f"   ✓ {name} ({r.get('conclusion', r.get('status'))}) - {r.get('url')}")
        sys.exit(0)
    else:
        print(f"🚨 [Sentinel CI Watchdog] Detected {report['failed_count']} FAILING workflows on branch '{report['branch']}':")
        for f in report["failures"]:
            print(f"\n❌ Workflow: {f['workflow']} (Commit: {f['commit']})")
            print(f"   Run URL: {f['url']}")
            print(f"   Log snippet:\n{f['log_snippet']}\n")
        sys.exit(1)

if __name__ == "__main__":
    main()
