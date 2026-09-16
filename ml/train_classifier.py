"""
Trains the log-category classifier.

Input: a newline-delimited JSON file of historical syslog lines (export one
from your existing LogAnalyzer database, or let the consumer accumulate raw
messages for a few days first). Each line needs at least a "message" field;
a "category" field is used as a ground-truth label when present, otherwise
the weak-supervision rules in labeling_rules.py generate a pseudo-label.

Usage:
    python train_classifier.py --input logs.jsonl --output /models/classifier.joblib

The model is a TF-IDF + linear SVM pipeline: cheap to train, cheap to run
per-message at 10M+ lines/day, and a reasonable baseline before reaching for
a heavier transformer-based classifier.
"""
import argparse
import json

import joblib
from sklearn.calibration import CalibratedClassifierCV
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.svm import LinearSVC
from sklearn.metrics import classification_report

from labeling_rules import weak_label


def load_dataset(path):
    messages, labels = [], []
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            record = json.loads(line)
            message = record.get("message", "")
            if not message:
                continue
            label = record.get("category") or weak_label(message)
            messages.append(message)
            labels.append(label)
    return messages, labels


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, help="Path to newline-delimited JSON log export")
    parser.add_argument("--output", required=True, help="Where to write the trained model (.joblib)")
    parser.add_argument("--test-size", type=float, default=0.2)
    args = parser.parse_args()

    messages, labels = load_dataset(args.input)
    if len(messages) < 100:
        raise SystemExit(
            f"Only {len(messages)} usable log lines found — need at least a few hundred "
            "to train a meaningful classifier. Let the consumer collect more raw traffic first."
        )

    x_train, x_test, y_train, y_test = train_test_split(
        messages, labels, test_size=args.test_size, random_state=42, stratify=labels
    )

    pipeline = Pipeline([
        ("tfidf", TfidfVectorizer(max_features=20000, ngram_range=(1, 2), min_df=2)),
        ("clf", CalibratedClassifierCV(LinearSVC(class_weight="balanced"), cv=3)),
    ])

    pipeline.fit(x_train, y_train)

    print(classification_report(y_test, pipeline.predict(x_test)))

    joblib.dump(pipeline, args.output)
    print(f"Model written to {args.output}")


if __name__ == "__main__":
    main()
