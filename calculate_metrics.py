import argparse
import csv
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, Iterable, List, Optional
from urllib.parse import urlparse


@dataclass
class GroundTruthRow:
    timestamp: datetime
    target_url: str
    is_real_up: bool


@dataclass
class PredictionRow:
    timestamp: datetime
    target_url: str
    is_up: Optional[bool]
    status_code: Optional[int]
    response_time: Optional[float]


@dataclass
class MatchResult:
    ground_truth: GroundTruthRow
    prediction: Optional[PredictionRow]


def normalize_target(value: str, mode: str) -> str:
    text = (value or "").strip().lower()
    if mode == "exact":
        return text.rstrip("/")

    parsed = urlparse(text)
    host = parsed.hostname or parsed.netloc
    if host:
        return host.lower()
    return text.rstrip("/")


def parse_iso_datetime(value: str) -> datetime:
    return datetime.fromisoformat(value.strip())


def parse_bool(value: object) -> Optional[bool]:
    if value is None:
        return None
    normalized = str(value).strip().lower()
    if normalized in {"true", "1", "yes", "y", "up"}:
        return True
    if normalized in {"false", "0", "no", "n", "down"}:
        return False
    return None


def parse_optional_int(value: object) -> Optional[int]:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    return int(float(text))


def parse_optional_float(value: object) -> Optional[float]:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    return float(text)


def load_ground_truth_rows(path: str) -> List[GroundTruthRow]:
    rows: List[GroundTruthRow] = []
    with open(path, newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        for raw in reader:
            timestamp = parse_iso_datetime(raw["timestamp"])
            target_url = raw["target_url"].strip()
            is_real_up = parse_bool(raw["is_real_up"])
            if is_real_up is None:
                raise ValueError(f"Invalid is_real_up value in ground truth: {raw['is_real_up']!r}")
            rows.append(
                GroundTruthRow(
                    timestamp=timestamp,
                    target_url=target_url,
                    is_real_up=is_real_up,
                )
            )
    rows.sort(key=lambda row: (row.target_url, row.timestamp))
    return rows


def load_predictions_from_csv(path: str) -> List[PredictionRow]:
    rows: List[PredictionRow] = []
    with open(path, newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        for raw in reader:
            timestamp = parse_iso_datetime(raw["timestamp"])
            target_url = raw["target_url"].strip()
            rows.append(
                PredictionRow(
                    timestamp=timestamp,
                    target_url=target_url,
                    is_up=parse_bool(raw.get("is_up")),
                    status_code=parse_optional_int(raw.get("status_code")),
                    response_time=parse_optional_float(raw.get("response_time")),
                )
            )
    rows.sort(key=lambda row: (row.target_url, row.timestamp))
    return rows


def load_predictions_from_db() -> List[PredictionRow]:
    from database import SessionLocal
    from models import Monitor, MonitorLog

    db = SessionLocal()
    try:
        query = (
            db.query(
                MonitorLog.checked_at,
                Monitor.target_url,
                MonitorLog.is_up,
                MonitorLog.status_code,
                MonitorLog.response_time,
            )
            .join(Monitor, Monitor.id == MonitorLog.monitor_id)
            .filter(MonitorLog.checked_at.isnot(None))
            .order_by(Monitor.target_url, MonitorLog.checked_at)
        )

        rows = [
            PredictionRow(
                timestamp=row.checked_at,
                target_url=(row.target_url or "").strip(),
                is_up=row.is_up,
                status_code=row.status_code,
                response_time=row.response_time,
            )
            for row in query.all()
            if row.target_url
        ]
        return rows
    finally:
        db.close()


def find_best_prediction(
    ground_truth: GroundTruthRow,
    candidates: Iterable[PredictionRow],
    max_time_diff_seconds: float,
) -> Optional[PredictionRow]:
    best_match: Optional[PredictionRow] = None
    best_diff: Optional[float] = None

    for candidate in candidates:
        if candidate.is_up is None:
            continue
        diff_seconds = abs((candidate.timestamp - ground_truth.timestamp).total_seconds())
        if diff_seconds > max_time_diff_seconds:
            continue
        if best_diff is None or diff_seconds < best_diff:
            best_match = candidate
            best_diff = diff_seconds

    return best_match


def match_predictions(
    ground_truth_rows: List[GroundTruthRow],
    prediction_rows: List[PredictionRow],
    max_time_diff_seconds: float,
    target_mode: str,
) -> List[MatchResult]:
    predictions_by_target: Dict[str, List[PredictionRow]] = {}
    for row in prediction_rows:
        normalized_target = normalize_target(row.target_url, target_mode)
        predictions_by_target.setdefault(normalized_target, []).append(row)

    matches: List[MatchResult] = []
    for truth in ground_truth_rows:
        normalized_target = normalize_target(truth.target_url, target_mode)
        candidates = predictions_by_target.get(normalized_target, [])
        prediction = find_best_prediction(truth, candidates, max_time_diff_seconds)
        matches.append(MatchResult(ground_truth=truth, prediction=prediction))
    return matches


def build_diagnostics(
    ground_truth_rows: List[GroundTruthRow],
    prediction_rows: List[PredictionRow],
    matches: List[MatchResult],
    target_mode: str,
) -> dict:
    gt_targets = {normalize_target(row.target_url, target_mode) for row in ground_truth_rows}
    pred_targets = {normalize_target(row.target_url, target_mode) for row in prediction_rows}
    overlapping_targets = sorted(gt_targets & pred_targets)

    gt_times = [row.timestamp for row in ground_truth_rows]
    pred_times = [row.timestamp for row in prediction_rows]

    return {
        "ground_truth_range": (
            min(gt_times).isoformat() if gt_times else None,
            max(gt_times).isoformat() if gt_times else None,
        ),
        "prediction_range": (
            min(pred_times).isoformat() if pred_times else None,
            max(pred_times).isoformat() if pred_times else None,
        ),
        "ground_truth_targets": len(gt_targets),
        "prediction_targets": len(pred_targets),
        "overlapping_targets": len(overlapping_targets),
        "sample_overlapping_targets": overlapping_targets[:10],
        "unmatched_rows": sum(1 for item in matches if item.prediction is None),
    }


def safe_percent(numerator: int, denominator: int) -> float:
    if denominator == 0:
        return 0.0
    return (numerator / denominator) * 100.0


def compute_metrics(matches: List[MatchResult]) -> dict:
    total_ground_truth = len(matches)
    matched = [item for item in matches if item.prediction is not None]

    true_positive = 0
    true_negative = 0
    false_positive = 0
    false_negative = 0

    structurally_valid = 0
    semantically_valid = 0

    for item in matched:
        prediction = item.prediction
        truth = item.ground_truth
        assert prediction is not None

        has_binary_decision = prediction.is_up is not None
        has_probe_context = prediction.status_code is not None or prediction.response_time is not None
        if has_binary_decision:
            structurally_valid += 1
        if has_binary_decision and has_probe_context:
            semantically_valid += 1

        actual_down = not truth.is_real_up
        predicted_down = not prediction.is_up

        if predicted_down and actual_down:
            true_positive += 1
        elif (not predicted_down) and (not actual_down):
            true_negative += 1
        elif predicted_down and (not actual_down):
            false_positive += 1
        else:
            false_negative += 1

    total_matched = len(matched)
    total_compared = true_positive + true_negative + false_positive + false_negative

    down_precision = safe_percent(true_positive, true_positive + false_positive)
    down_recall = safe_percent(true_positive, true_positive + false_negative)
    up_precision = safe_percent(true_negative, true_negative + false_negative)
    up_recall = safe_percent(true_negative, true_negative + false_positive)
    accuracy = safe_percent(true_positive + true_negative, total_compared)
    validity = safe_percent(semantically_valid, total_ground_truth)
    coverage = safe_percent(total_matched, total_ground_truth)

    f1_down = 0.0
    if down_precision + down_recall > 0:
        f1_down = 2 * (down_precision * down_recall) / (down_precision + down_recall)

    return {
        "total_ground_truth": total_ground_truth,
        "matched_predictions": total_matched,
        "coverage": coverage,
        "structural_validity": safe_percent(structurally_valid, total_ground_truth),
        "validity": validity,
        "accuracy": accuracy,
        "down_precision": down_precision,
        "down_recall": down_recall,
        "down_f1": f1_down,
        "up_precision": up_precision,
        "up_recall": up_recall,
        "tp": true_positive,
        "tn": true_negative,
        "fp": false_positive,
        "fn": false_negative,
    }


def print_metrics(metrics: dict) -> None:
    print(f"Ground-truth rows: {metrics['total_ground_truth']}")
    print(f"Matched predictions: {metrics['matched_predictions']}")
    print(f"Coverage: {metrics['coverage']:.2f}%")
    print(f"Structural validity: {metrics['structural_validity']:.2f}%")
    print(f"Validity: {metrics['validity']:.2f}%")
    print(f"Accuracy: {metrics['accuracy']:.2f}%")
    print(f"Down precision: {metrics['down_precision']:.2f}%")
    print(f"Down recall: {metrics['down_recall']:.2f}%")
    print(f"Down F1: {metrics['down_f1']:.2f}%")
    print(f"Up precision: {metrics['up_precision']:.2f}%")
    print(f"Up recall: {metrics['up_recall']:.2f}%")
    print(
        "Confusion matrix (positive class = DOWN): "
        f"TP={metrics['tp']} TN={metrics['tn']} FP={metrics['fp']} FN={metrics['fn']}"
    )


def print_diagnostics(diagnostics: dict) -> None:
    gt_start, gt_end = diagnostics["ground_truth_range"]
    pred_start, pred_end = diagnostics["prediction_range"]
    print(
        "Ground-truth time range: "
        f"{gt_start or 'N/A'} to {gt_end or 'N/A'}"
    )
    print(
        "Prediction time range: "
        f"{pred_start or 'N/A'} to {pred_end or 'N/A'}"
    )
    print(
        "Unique targets: "
        f"ground truth={diagnostics['ground_truth_targets']} "
        f"predictions={diagnostics['prediction_targets']} "
        f"overlap={diagnostics['overlapping_targets']}"
    )
    if diagnostics["sample_overlapping_targets"]:
        print(
            "Sample overlapping targets: "
            + ", ".join(diagnostics["sample_overlapping_targets"])
        )


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Evaluate binary up/down detection against labeled ground truth."
    )
    parser.add_argument(
        "--ground-truth",
        default="ground_truth.csv",
        help="Path to the labeled ground-truth CSV.",
    )
    parser.add_argument(
        "--predictions-csv",
        default=None,
        help="Optional path to a prediction CSV with timestamp,target_url,is_up,status_code,response_time.",
    )
    parser.add_argument(
        "--max-time-diff-seconds",
        type=float,
        default=15.0,
        help="Maximum allowed timestamp difference when matching a prediction to a ground-truth row.",
    )
    parser.add_argument(
        "--target-mode",
        choices=["exact", "host"],
        default="host",
        help="Match targets by exact URL or by normalized hostname.",
    )
    return parser


def main() -> None:
    parser = build_argument_parser()
    args = parser.parse_args()

    ground_truth_rows = load_ground_truth_rows(args.ground_truth)

    if args.predictions_csv:
        prediction_rows = load_predictions_from_csv(args.predictions_csv)
    else:
        prediction_rows = load_predictions_from_db()

    matches = match_predictions(
        ground_truth_rows=ground_truth_rows,
        prediction_rows=prediction_rows,
        max_time_diff_seconds=args.max_time_diff_seconds,
        target_mode=args.target_mode,
    )
    metrics = compute_metrics(matches)
    print_metrics(metrics)
    print_diagnostics(
        build_diagnostics(
            ground_truth_rows=ground_truth_rows,
            prediction_rows=prediction_rows,
            matches=matches,
            target_mode=args.target_mode,
        )
    )


if __name__ == "__main__":
    main()
