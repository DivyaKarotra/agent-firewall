"""
TF-IDF + Logistic Regression classifier for prompt injection detection.

Optional dependency: requires scikit-learn and joblib.
The cascade works without this module.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

_HAS_SKLEARN = False
try:
    import joblib  # type: ignore
    from sklearn.feature_extraction.text import TfidfVectorizer  # type: ignore
    from sklearn.linear_model import LogisticRegression  # type: ignore
    from sklearn.pipeline import Pipeline  # type: ignore
    _HAS_SKLEARN = True
except ImportError:
    pass

MODEL_DIR = Path(__file__).parent.parent / "models"
MODEL_PATH = MODEL_DIR / "classifier.joblib"


def is_available() -> bool:
    """Return True if scikit-learn is installed."""
    return _HAS_SKLEARN


class Classifier:
    """TF-IDF + Logistic Regression prompt-injection classifier."""

    def __init__(self) -> None:
        if not _HAS_SKLEARN:
            raise ImportError(
                "scikit-learn is required for the classifier. "
                "Install it with: pip install agent-firewall[ml]"
            )
        self._pipeline: Optional[Pipeline] = None

    @property
    def is_fitted(self) -> bool:
        return self._pipeline is not None

    def train(
        self,
        texts: list[str],
        labels: list[int],
        calibrate: bool = True,
        calibration_method: str = "sigmoid",
        cv: int = 5,
    ) -> dict:
        """
        Train the classifier on *texts* with binary *labels* (1=attack, 0=normal).
        When *calibrate* is True, fits cross-validated Platt scaling or isotonic calibration.
        Returns a dict with training metadata.
        """
        word_tfidf = TfidfVectorizer(
            analyzer="word",
            ngram_range=(1, 3),
            max_features=10000,
            sublinear_tf=True,
        )
        char_tfidf = TfidfVectorizer(
            analyzer="char_wb",
            ngram_range=(3, 5),
            max_features=15000,
            sublinear_tf=True,
        )
        from sklearn.pipeline import FeatureUnion, Pipeline  # type: ignore

        features = FeatureUnion([
            ("word", word_tfidf),
            ("char", char_tfidf),
        ])

        base_pipeline = Pipeline([
            ("features", features),
            ("clf", LogisticRegression(
                C=1.0,
                max_iter=1000,
                solver="lbfgs",
                class_weight="balanced",
            )),
        ])

        if calibrate:
            from sklearn.calibration import CalibratedClassifierCV  # type: ignore

            self._pipeline = CalibratedClassifierCV(
                estimator=base_pipeline,
                method=calibration_method,
                cv=cv,
            )
        else:
            self._pipeline = base_pipeline

        self._pipeline.fit(texts, labels)
        return {
            "n_samples": len(texts),
            "n_attacks": sum(labels),
            "calibrated": calibrate,
            "calibration_method": calibration_method if calibrate else None,
        }

    def reliability_summary(self, texts: list[str], labels: list[int], n_bins: int = 5) -> dict:
        """Compute calibration metrics: Brier score, log loss, and calibration curve."""
        from sklearn.calibration import calibration_curve  # type: ignore
        from sklearn.metrics import brier_score_loss, log_loss  # type: ignore

        probs = [self.predict_proba(t) for t in texts]
        brier = float(brier_score_loss(labels, probs))
        loss = float(log_loss(labels, probs))
        prob_true, prob_pred = calibration_curve(labels, probs, n_bins=n_bins)
        bins = [{"predicted": float(p), "empirical": float(t)} for p, t in zip(prob_pred, prob_true)]
        return {
            "brier_score": brier,
            "log_loss": loss,
            "bins": bins,
        }

    def predict_proba(self, text: str) -> float:
        """Return probability that *text* is a prompt injection (0..1)."""
        if self._pipeline is None:
            raise RuntimeError("Classifier is not trained. Call train() or load() first.")
        proba = self._pipeline.predict_proba([text])[0]
        # Column 1 = attack probability
        return float(proba[1])

    def save(self, path: Optional[Path] = None) -> Path:
        """Save the trained model to disk."""
        path = path or MODEL_PATH
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self._pipeline, path)
        return path

    def load(self, path: Optional[Path] = None) -> None:
        """Load a trained model from disk."""
        path = path or MODEL_PATH
        if not path.exists():
            raise FileNotFoundError(f"No classifier model at {path}")
        self._pipeline = joblib.load(path)


def load_data(data_dir: Optional[Path] = None) -> tuple[list[str], list[int], list[str], list[int]]:
    """
    Load training/test data from JSONL files in *data_dir*.

    Returns (train_texts, train_labels, test_texts, test_labels).
    Labels: 1 = attack, 0 = normal.
    """
    if data_dir is None:
        data_dir = Path(__file__).parent.parent / "data"

    train_texts: list[str] = []
    train_labels: list[int] = []
    test_texts: list[str] = []
    test_labels: list[int] = []

    for jsonl_file in sorted(data_dir.glob("*.jsonl")):
        if jsonl_file.name == "fresh_test.jsonl":
            continue
        with open(jsonl_file, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                item = json.loads(line)
                label = 1 if item["label"] == "attack" else 0
                text = item["text"]
                split = item.get("split", "dev")
                if split == "test":
                    test_texts.append(text)
                    test_labels.append(label)
                else:
                    train_texts.append(text)
                    train_labels.append(label)

    return train_texts, train_labels, test_texts, test_labels
