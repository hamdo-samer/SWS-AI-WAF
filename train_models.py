"""Train the request classifier on the local, labeled CSIC CSV dataset."""

from __future__ import annotations

import argparse
import csv
import importlib
import json
import math
import sys
from pathlib import Path
from typing import Any

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split

from request_features import format_request_text


PROJECT_ROOT = Path(__file__).parent
DEFAULT_DATASET = PROJECT_ROOT / "data" / "csic_database.csv"
DEFAULT_MODEL_DIRECTORY = PROJECT_ROOT / "models"
RANDOM_STATE = 42
_NORMAL_REQUEST_REPETITIONS = 64
_NORMAL_REQUESTS = (
    ("GET", "/"),
    ("GET", "/index.html"),
    ("GET", "/hakkimizda.html"),
    ("GET", "/hizmetler.html"),
    ("GET", "/iletisim.html"),
    ("GET", "/css/style.css"),
    ("GET", "/img/logo.jpg"),
    ("GET", "/img/hero-bg.jpg"),
    ("GET", "/img/mutfak.jpg"),
    ("POST", "/iletisim.html"),
    ("POST", "/contact"),
    ("POST", "/api/contact"),
    ("POST", "/iletisim.html?subject=mutfak"),
)


def load_dataset(path: str | Path = DEFAULT_DATASET) -> tuple[list[str], np.ndarray]:
    dataset_path = Path(path)
    if not dataset_path.is_file():
        raise FileNotFoundError(
            f"Dataset not found: {dataset_path}. Add data/csic_database.csv first."
        )

    texts: list[str] = []
    labels: list[int] = []
    with dataset_path.open(encoding="utf-8-sig", errors="replace", newline="") as dataset:
        reader = csv.DictReader(dataset)
        if not reader.fieldnames:
            raise ValueError("The dataset CSV must have a header row.")

        label_column = next(
            (column for column in reader.fieldnames if column.strip().lower() == "classification"),
            None,
        )
        if label_column is None:
            raise ValueError("The dataset must contain a 'classification' column.")
        columns_by_name = {
            column.strip().casefold(): column
            for column in reader.fieldnames
            if column and column != label_column
        }
        method_column = columns_by_name.get("method")
        url_column = columns_by_name.get("url")
        if method_column is None or url_column is None:
            raise ValueError("The dataset must contain 'Method' and 'URL' columns.")

        for row_number, row in enumerate(reader, start=2):
            raw_label = (row.get(label_column) or "").strip()
            if raw_label not in {"0", "1"}:
                raise ValueError(
                    f"Unsupported classification {raw_label!r} on CSV row {row_number}; "
                    "expected 0 (normal) or 1 (anomalous)."
                )
            request_text = format_request_text(
                row.get(method_column) or "",
                row.get(url_column) or "",
            )
            if request_text:
                texts.append(request_text)
                labels.append(int(raw_label))

    if not texts:
        raise ValueError("The dataset contains no non-empty request rows.")
    if set(labels) != {0, 1}:
        raise ValueError("The dataset must contain both normal (0) and anomalous (1) rows.")
    return texts, np.asarray(labels, dtype=np.int32)


def _calculate_metrics(labels: np.ndarray, predictions: np.ndarray) -> dict[str, Any]:
    true_negative, false_positive, _, _ = confusion_matrix(
        labels,
        predictions,
        labels=(0, 1),
    ).ravel()
    return {
        "accuracy": float(accuracy_score(labels, predictions)),
        "precision": float(precision_score(labels, predictions, zero_division=0)),
        "recall": float(recall_score(labels, predictions, zero_division=0)),
        "f1": float(f1_score(labels, predictions, zero_division=0)),
        "false_positive_rate": float(
            false_positive / (false_positive + true_negative)
            if false_positive + true_negative
            else 0
        ),
        "classification_report": classification_report(
            labels,
            predictions,
            labels=(0, 1),
            target_names=("Normal", "Anomalous"),
            output_dict=True,
            zero_division=0,
        ),
    }


def _deduplicate_requests(
    texts: list[str],
    labels: np.ndarray,
) -> tuple[list[str], np.ndarray, int]:
    labels_by_text: dict[str, set[int]] = {}
    for text, label in zip(texts, labels):
        labels_by_text.setdefault(text, set()).add(int(label))

    conflicting_texts = {
        text for text, text_labels in labels_by_text.items() if len(text_labels) > 1
    }
    unique_texts: list[str] = []
    unique_labels: list[int] = []
    seen: set[str] = set()
    for text, label in zip(texts, labels):
        if text in seen or text in conflicting_texts:
            continue
        seen.add(text)
        unique_texts.append(text)
        unique_labels.append(int(label))

    if set(unique_labels) != {0, 1}:
        raise ValueError(
            "The dataset must contain both classes after duplicate requests with "
            "conflicting labels are excluded."
        )
    return unique_texts, np.asarray(unique_labels, dtype=np.int32), len(conflicting_texts)


def _augment_training_with_normal_requests(
    training_texts: list[str],
    training_labels: np.ndarray,
    heldout_texts: list[str],
) -> tuple[list[str], np.ndarray, int]:
    heldout = set(heldout_texts)
    normal_texts = []
    for method, url in _NORMAL_REQUESTS:
        text = format_request_text(method, url)
        if text not in heldout:
            normal_texts.append(text)
    repeated_texts = normal_texts * _NORMAL_REQUEST_REPETITIONS
    repeated_labels = np.zeros(len(repeated_texts), dtype=np.int32)
    return (
        [*training_texts, *repeated_texts],
        np.concatenate((training_labels, repeated_labels)),
        len(normal_texts),
    )


def _tensorflow() -> Any:
    try:
        return importlib.import_module("tensorflow")
    except ImportError as error:
        raise RuntimeError(
            "TensorFlow is required for CNN training. Install requirements-training.txt "
            "in a supported Python environment."
        ) from error


def _sparse_dataset(
    tensorflow: Any,
    features: Any,
    labels: np.ndarray,
    batch_size: int,
    shuffle: bool,
) -> Any:
    rng = np.random.default_rng(RANDOM_STATE)

    def batches():
        indices = np.arange(len(labels))
        if shuffle:
            rng.shuffle(indices)
        for start in range(0, len(indices), batch_size):
            selected = indices[start : start + batch_size]
            dense = features[selected].toarray().astype(np.float32, copy=False)
            yield dense.reshape((len(selected), dense.shape[1], 1)), labels[selected].astype(
                np.float32, copy=False
            )

    dataset = tensorflow.data.Dataset.from_generator(
        batches,
        output_signature=(
            tensorflow.TensorSpec((None, features.shape[1], 1), dtype=tensorflow.float32),
            tensorflow.TensorSpec((None,), dtype=tensorflow.float32),
        ),
    )
    return dataset.repeat().prefetch(tensorflow.data.AUTOTUNE)


def train_models(
    dataset_path: str | Path = DEFAULT_DATASET,
    model_directory: str | Path = DEFAULT_MODEL_DIRECTORY,
) -> dict[str, dict[str, Any]]:
    tensorflow = _tensorflow()
    loaded_texts, loaded_labels = load_dataset(dataset_path)
    texts, labels, conflicting_request_count = _deduplicate_requests(
        loaded_texts, loaded_labels
    )
    if conflicting_request_count:
        print(
            "Warning: excluded "
            f"{conflicting_request_count} unique requests with conflicting labels.",
            file=sys.stderr,
        )
    x_train, x_test, y_train, y_test = train_test_split(
        texts,
        labels,
        test_size=0.2,
        random_state=RANDOM_STATE,
        stratify=labels,
    )
    x_cnn_train, x_cnn_validation, y_cnn_train, y_cnn_validation = train_test_split(
        x_train,
        y_train,
        test_size=0.1,
        random_state=RANDOM_STATE,
        stratify=y_train,
    )
    x_train, y_train, synthetic_normal_patterns = _augment_training_with_normal_requests(
        x_train,
        y_train,
        x_test,
    )
    x_cnn_train, y_cnn_train, cnn_synthetic_normal_patterns = (
        _augment_training_with_normal_requests(
            x_cnn_train,
            y_cnn_train,
            x_test,
        )
    )
    if cnn_synthetic_normal_patterns != synthetic_normal_patterns:
        raise RuntimeError("RF and CNN training data received different normal examples.")

    vectorizer = TfidfVectorizer(
        analyzer="char",
        ngram_range=(2, 4),
        max_features=5000,
        dtype=np.float32,
    )
    vectorizer.fit(x_cnn_train)
    x_train_vectors = vectorizer.transform(x_train)
    x_test_vectors = vectorizer.transform(x_test)
    x_cnn_train_vectors = vectorizer.transform(x_cnn_train)
    x_cnn_validation_vectors = vectorizer.transform(x_cnn_validation)

    rf_model = RandomForestClassifier(
        n_estimators=100,
        random_state=RANDOM_STATE,
        n_jobs=-1,
    )
    rf_model.fit(x_train_vectors, y_train)
    rf_predictions = rf_model.predict(x_test_vectors)
    metrics: dict[str, dict[str, Any]] = {
        "Random Forest": _calculate_metrics(y_test, rf_predictions)
    }

    if x_train_vectors.shape[1] < 8:
        raise ValueError("The dataset produced too few text features to train the CNN.")
    tensorflow.keras.utils.set_random_seed(RANDOM_STATE)
    batch_size = 64
    train_dataset = _sparse_dataset(
        tensorflow, x_cnn_train_vectors, y_cnn_train, batch_size, shuffle=True
    )
    validation_dataset = _sparse_dataset(
        tensorflow, x_cnn_validation_vectors, y_cnn_validation, batch_size, shuffle=False
    )
    test_dataset = _sparse_dataset(
        tensorflow, x_test_vectors, y_test, batch_size, shuffle=False
    )

    cnn_model = tensorflow.keras.models.Sequential(
        [
            tensorflow.keras.layers.Input(shape=(x_train_vectors.shape[1], 1)),
            tensorflow.keras.layers.Conv1D(64, 3, activation="relu"),
            tensorflow.keras.layers.MaxPooling1D(2),
            tensorflow.keras.layers.Dropout(0.3),
            tensorflow.keras.layers.Conv1D(32, 3, activation="relu"),
            tensorflow.keras.layers.MaxPooling1D(2),
            tensorflow.keras.layers.Flatten(),
            tensorflow.keras.layers.Dense(64, activation="relu"),
            tensorflow.keras.layers.Dropout(0.4),
            tensorflow.keras.layers.Dense(1, activation="sigmoid"),
        ]
    )
    cnn_model.compile(
        optimizer=tensorflow.keras.optimizers.Adam(learning_rate=0.001),
        loss="binary_crossentropy",
        metrics=["accuracy"],
    )
    cnn_model.fit(
        train_dataset,
        epochs=5,
        validation_data=validation_dataset,
        steps_per_epoch=math.ceil(len(y_cnn_train) / batch_size),
        validation_steps=math.ceil(len(y_cnn_validation) / batch_size),
        verbose=2,
        shuffle=False,
    )
    cnn_probabilities = cnn_model.predict(
        test_dataset,
        steps=math.ceil(len(y_test) / batch_size),
        verbose=0,
    ).reshape(-1)
    cnn_predictions = (cnn_probabilities >= 0.5).astype(np.int32)
    metrics["1D-CNN"] = _calculate_metrics(y_test, cnn_predictions)
    evaluation_metadata = {
        "split_strategy": "deduplicated_request_stratified_holdout_with_train_only_normal_augmentation",
        "input_rows": len(loaded_texts),
        "unique_requests": len(texts),
        "conflicting_request_groups_excluded": conflicting_request_count,
        "test_unique_requests": len(y_test),
        "synthetic_normal_training_patterns": synthetic_normal_patterns,
        "synthetic_normal_training_examples": (
            synthetic_normal_patterns * _NORMAL_REQUEST_REPETITIONS
        ),
    }
    for scores in metrics.values():
        scores["evaluation"] = evaluation_metadata

    output_directory = Path(model_directory)
    output_directory.mkdir(parents=True, exist_ok=True)
    joblib.dump(vectorizer, output_directory / "vectorizer.joblib")
    joblib.dump(rf_model, output_directory / "random_forest.joblib")
    cnn_model.save(output_directory / "1d_cnn.keras")
    (output_directory / "metrics.json").write_text(
        json.dumps(metrics, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    print(
        f"Loaded {len(loaded_texts)} rows; trained RF on {len(y_train)} examples "
        f"including {synthetic_normal_patterns * _NORMAL_REQUEST_REPETITIONS} "
        f"synthetic normal examples and CNN on {len(y_cnn_train)} examples "
        f"from {dataset_path}."
    )
    for model_name, scores in metrics.items():
        print(
            f"{model_name}: accuracy={scores['accuracy']:.4f}, "
            f"precision={scores['precision']:.4f}, recall={scores['recall']:.4f}, "
            f"F1={scores['f1']:.4f}"
        )
    print(f"Saved trained models and held-out metrics in {output_directory}.")
    return metrics


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", type=Path, default=DEFAULT_DATASET)
    parser.add_argument("--model-dir", type=Path, default=DEFAULT_MODEL_DIRECTORY)
    arguments = parser.parse_args(argv)
    try:
        train_models(arguments.data, arguments.model_dir)
    except (FileNotFoundError, RuntimeError, ValueError) as error:
        print(f"Training failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
