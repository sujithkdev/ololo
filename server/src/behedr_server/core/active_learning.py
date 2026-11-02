# server/core/active_learning.py — Alert Feedback & ML Model Improvement
"""
PRIORITY 4: Active Learning & Feedback Loop

Analysts mark alerts as True Positive or False Positive. The system:
1. Tracks feedback in the database
2. Reports reviewed-alert precision and false-positive patterns
3. Provides suppression suggestions for manual review
4. Explicitly reports feedback retraining as unavailable

Feedback is collected for analyst review. Automated feedback retraining is
not implemented; no measured accuracy improvement is claimed.
"""

import time
import threading
from collections import defaultdict, Counter
from typing import Dict, List, Tuple, Optional

# ── Feedback storage ──────────────────────────────────────────────────────────

_feedback: Dict[int, dict] = {}  # alert_id → {verdict, username, timestamp, reason}
_feedback_lock = threading.Lock()

# ── Feedback stats for tracking improvement ───────────────────────────────────

_stats = {
    "total_feedback": 0,
    "true_positives": 0,
    "false_positives": 0,
    "accuracy_week1": 0.0,
    "accuracy_current": 0.0,
    "last_retrain": 0,
}
_stats_lock = threading.Lock()


def record_feedback(alert_id: int, verdict: str, username: str, reason: str = "") -> bool:
    """
    Record analyst feedback for an alert.

    Args:
        alert_id: Alert ID from database
        verdict: "true_positive" or "false_positive"
        username: Analyst who provided feedback
        reason: Optional explanation

    Returns:
        True if feedback recorded successfully
    """
    if verdict not in ("true_positive", "false_positive"):
        return False

    with _feedback_lock:
        previous = _feedback.get(alert_id)
        _feedback[alert_id] = {
            "verdict": verdict,
            "username": username,
            "timestamp": int(time.time()),
            "reason": reason,
        }

        # Update stats
        with _stats_lock:
            if previous is None:
                _stats["total_feedback"] += 1
            else:
                old_key = "true_positives" if previous["verdict"] == "true_positive" else "false_positives"
                _stats[old_key] -= 1
            if verdict == "true_positive":
                _stats["true_positives"] += 1
            else:
                _stats["false_positives"] += 1

            # Calculate current accuracy
            if _stats["total_feedback"] > 0:
                _stats["accuracy_current"] = _stats["true_positives"] / _stats["total_feedback"]

            # Set week 1 baseline
            if previous is None and _stats["total_feedback"] == 10:  # After first 10 samples
                _stats["accuracy_week1"] = _stats["accuracy_current"]

        # Persist to database
        try:
            from behedr_server.database.storage import save_alert_feedback
            save_alert_feedback(alert_id, verdict, username, reason)
        except Exception as e:
            print(f"[ACTIVE LEARNING] Could not persist feedback: {e}")

    # Check if we should trigger retraining
    _maybe_retrain()

    print(f"[ACTIVE LEARNING] Feedback recorded: Alert {alert_id} → {verdict} by {username}")
    return True


def get_feedback(alert_id: int) -> Optional[dict]:
    """Get feedback for a specific alert."""
    with _feedback_lock:
        return _feedback.get(alert_id)


def get_all_feedback() -> List[dict]:
    """Get all feedback records."""
    with _feedback_lock:
        return [
            {"alert_id": aid, **data}
            for aid, data in _feedback.items()
        ]


def get_stats() -> dict:
    """Get feedback statistics and accuracy metrics."""
    with _stats_lock:
        return {**_stats, "metric": "precision_among_reviewed_alerts",
                "feedback_retraining_available": False}


# ── Auto-adjustment based on feedback ─────────────────────────────────────────

def _adjust_detection_weights():
    """
    Adjust heuristic weights and ML thresholds based on false positive patterns.

    Analyzes false positive feedback to identify common patterns:
    - If many FPs involve PowerShell → reduce PowerShell weight for dev machines
    - If many FPs involve specific parent-child pairs → add to safe list
    - If ML layer has high FP rate → increase anomaly threshold
    """
    with _feedback_lock:
        fp_alerts = [aid for aid, fb in _feedback.items() if fb["verdict"] == "false_positive"]

    if len(fp_alerts) < 5:  # Need at least 5 FPs to identify patterns
        return

    # Fetch alert details from database
    try:
        from behedr_server.database.storage import get_alert_by_id
        fp_data = [get_alert_by_id(aid) for aid in fp_alerts[-50:]]  # Last 50 FPs
        fp_data = [a for a in fp_data if a]  # Filter None values
    except Exception as e:
        print(f"[ACTIVE LEARNING] Could not fetch FP alerts: {e}")
        return

    # Analyze patterns
    process_counts = Counter()
    reason_patterns = Counter()

    for alert in fp_data:
        process_counts[alert.get("process", "").lower()] += 1
        reason = alert.get("reason", "")
        # Extract reason prefix (e.g., "HEURISTIC: " or "L2: ")
        if ":" in reason:
            prefix = reason.split(":")[0] + ":"
            reason_patterns[prefix] += 1

    # Auto-create suppressions for high-FP processes
    for process, count in process_counts.items():
        if count >= 5 and process:  # 5+ FPs for same process
            print(f"[ACTIVE LEARNING] Suggested suppression for high-FP process: {process}")
            # This would add to suppression list in production
            # For now, just log it

    # Log patterns for manual review
    print(f"[ACTIVE LEARNING] FP analysis: {len(fp_alerts)} false positives")
    print(f"  Top FP processes: {dict(list(process_counts.most_common(5)))}")
    print(f"  Top FP reasons: {dict(list(reason_patterns.most_common(5)))}")


# ── ML Model Retraining with Feedback ─────────────────────────────────────────

_RETRAIN_THRESHOLD = 100  # Retrain after every 100 feedback samples
_last_retrain_count = 0


def _maybe_retrain():
    """Check if we should trigger ML model retraining."""
    global _last_retrain_count

    with _stats_lock:
        total = _stats["total_feedback"]

    if total - _last_retrain_count >= _RETRAIN_THRESHOLD:
        threading.Thread(target=_retrain_with_feedback, daemon=True).start()
        _last_retrain_count = total


def _retrain_with_feedback():
    """Explicitly unavailable until model-specific feedback training is implemented."""
    print("[ACTIVE LEARNING] Feedback retraining unavailable; models unchanged")
    return False


# ── Feedback-driven suppression suggestions ───────────────────────────────────

def get_suppression_suggestions() -> List[dict]:
    """
    Analyze false positive patterns and suggest suppressions.

    Returns list of suggested suppressions:
    [
        {
            "system_id": "PC-01",
            "process": "powershell.exe",
            "reason_prefix": "HEURISTIC:",
            "fp_count": 8,
            "confidence": "HIGH"
        },
        ...
    ]
    """
    with _feedback_lock:
        fp_alerts = [aid for aid, fb in _feedback.items() if fb["verdict"] == "false_positive"]

    if len(fp_alerts) < 3:
        return []

    try:
        from behedr_server.database.storage import get_alert_by_id
        fp_data = [get_alert_by_id(aid) for aid in fp_alerts[-100:]]  # Last 100 FPs
        fp_data = [a for a in fp_data if a]
    except Exception:
        return []

    # Group by (system_id, process, reason_prefix)
    patterns = defaultdict(list)
    for alert in fp_data:
        system_id = alert.get("system_id", "")
        process = alert.get("process", "").lower()
        reason = alert.get("reason", "")

        # Extract reason prefix
        if ":" in reason:
            reason_prefix = reason.split(":")[0] + ":"
        else:
            reason_prefix = reason[:30]

        key = (system_id, process, reason_prefix)
        patterns[key].append(alert)

    # Generate suggestions for patterns with 3+ occurrences
    suggestions = []
    for (system_id, process, reason_prefix), alerts in patterns.items():
        if len(alerts) >= 3:
            suggestions.append({
                "system_id": system_id,
                "process": process,
                "reason_prefix": reason_prefix,
                "fp_count": len(alerts),
                "confidence": "HIGH" if len(alerts) >= 5 else "MEDIUM",
                "sample_alert_id": alerts[0].get("id"),
            })

    # Sort by FP count descending
    suggestions.sort(key=lambda x: x["fp_count"], reverse=True)

    return suggestions


# ── Accuracy tracking over time ───────────────────────────────────────────────

def get_accuracy_trend() -> dict:
    """
    Calculate accuracy improvement over time.

    Returns:
    {
        "week1_accuracy": 0.80,    # First 10-50 samples
        "current_accuracy": 0.95,  # Latest 50 samples
        "improvement": "+15%",
        "total_samples": 250,
        "true_positives": 215,
        "false_positives": 35
    }
    """
    with _stats_lock:
        stats = dict(_stats)

    improvement = 0.0
    if stats["accuracy_week1"] > 0:
        improvement = (stats["accuracy_current"] - stats["accuracy_week1"]) * 100

    return {
        "metric": "precision_among_reviewed_alerts",
        "feedback_retraining_available": False,
        "week1_accuracy": round(stats["accuracy_week1"], 3),
        "current_accuracy": round(stats["accuracy_current"], 3),
        "improvement": f"+{improvement:.1f}%" if improvement > 0 else f"{improvement:.1f}%",
        "total_samples": stats["total_feedback"],
        "true_positives": stats["true_positives"],
        "false_positives": stats["false_positives"],
        "last_retrain": stats["last_retrain"],
    }


# ── Initialize from database on startup ───────────────────────────────────────

def initialize():
    """Load existing feedback from database on server startup."""
    try:
        from behedr_server.database.storage import load_all_feedback
        feedback_list = load_all_feedback()

        with _feedback_lock:
            for fb in feedback_list:
                _feedback[fb["alert_id"]] = {
                    "verdict": fb["verdict"],
                    "username": fb["username"],
                    "timestamp": fb["timestamp"],
                    "reason": fb.get("reason", ""),
                }

        # Recalculate stats
        with _stats_lock:
            _stats["total_feedback"] = len(_feedback)
            _stats["true_positives"] = sum(
                1 for fb in _feedback.values() if fb["verdict"] == "true_positive"
            )
            _stats["false_positives"] = sum(
                1 for fb in _feedback.values() if fb["verdict"] == "false_positive"
            )
            if _stats["total_feedback"] > 0:
                _stats["accuracy_current"] = _stats["true_positives"] / _stats["total_feedback"]

            # Calculate week1 accuracy from first 10 samples
            if _stats["total_feedback"] >= 10:
                first_10 = list(_feedback.values())[:10]
                tp_first_10 = sum(1 for fb in first_10 if fb["verdict"] == "true_positive")
                _stats["accuracy_week1"] = tp_first_10 / 10

        print(f"[ACTIVE LEARNING] Initialized with {len(_feedback)} feedback records")
        print(f"[ACTIVE LEARNING] Current accuracy: {_stats['accuracy_current']:.1%}")

    except Exception as e:
        print(f"[ACTIVE LEARNING] Could not load feedback from database: {e}")
        print("[ACTIVE LEARNING] Starting with empty feedback database")


# Auto-initialize on module load
# initialize()  # Commented out - will be called explicitly from detector.py
