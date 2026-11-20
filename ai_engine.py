"""Optional local inference for trusted Random Forest and 1D-CNN model files."""

from __future__ import annotations

import importlib
import logging
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from request_features import format_request_text


@dataclass(frozen=True)
class AIPrediction:
    rf_decision: str | None
    rf_confidence: float | None
    dl_decision: str | None
    dl_confidence: float | None


class _Vectorizer(Protocol):
    def transform(self, values: Sequence[str]) -> Any: ...


class _Classifier(Protocol):
    def predict(self, features: Any) -> Sequence[object]: ...

    def predict_proba(self, features: Any) -> Sequence[Sequence[float]]: ...


class AIDetector:
    def __init__(
        self,
        model_path: str | Path | None = None,
        vectorizer_path: str | Path | None = None,
        cnn_model_path: str | Path | None = None,
    ) -> None:
        models_directory = Path(__file__).parent / "models"
        self.model_path = Path(model_path) if model_path else models_directory / "random_forest.joblib"
        self.vectorizer_path = (
            Path(vectorizer_path) if vectorizer_path else models_directory / "vectorizer.joblib"
        )
        self.cnn_model_path = (
            Path(cnn_model_path) if cnn_model_path else models_directory / "1d_cnn.keras"
        )
        self._model: _Classifier | None = None
        self._vectorizer: _Vectorizer | None = None
        self._cnn_model: Any | None = None
        self._supports_probabilities = False

        has_rf_model = self.model_path.is_file()
        has_cnn_model = self.cnn_model_path.is_file()
        if not has_rf_model and not has_cnn_model:
            return
        if not self.vectorizer_path.is_file():
            raise FileNotFoundError(
                f"The trained vectorizer is required: {self.vectorizer_path}"
            )

        try:
            joblib = importlib.import_module("joblib")
        except ImportError as error:
            raise RuntimeError(
                "Install the declared joblib dependency to load the trained vectorizer."
            ) from error
        self._vectorizer = joblib.load(self.vectorizer_path)
        if not callable(getattr(self._vectorizer, "transform", None)):
            raise TypeError("The configured vectorizer must provide transform().")

        if has_rf_model:
            self._model = joblib.load(self.model_path)
            if not callable(getattr(self._model, "predict", None)):
                raise TypeError("The configured Random Forest model must provide predict().")
            self._supports_probabilities = callable(
                getattr(self._model, "predict_proba", None)
            )

        if has_cnn_model:
            try:
                tensorflow = importlib.import_module("tensorflow")
            except ImportError:
                logging.getLogger(__name__).warning(
                    "CNN model is unavailable because TensorFlow is not installed; "
                    "install requirements-training.txt to enable it."
                )
            else:
                self._cnn_model = tensorflow.keras.models.load_model(self.cnn_model_path)

    @property
    def is_available(self) -> bool:
        return (
            self._vectorizer is not None
            and (self._model is not None or self._cnn_model is not None)
        )

    @property
    def rf_available(self) -> bool:
        return self._model is not None

    @property
    def dl_available(self) -> bool:
        return self._cnn_model is not None

    @staticmethod
    def _decision(label: object) -> str:
        if str(label) == "0":
            return "İzin verildi"
        if str(label) == "1":
            return "Engellendi"
        raise ValueError(f"Unsupported model class {label!r}; expected binary labels 0 and 1.")

    def predict(
        self,
        method: str,
        path: str,
        query: str = "",
    ) -> AIPrediction:
        model = self._model
        cnn_model = self._cnn_model
        vectorizer = self._vectorizer
        if vectorizer is None or (model is None and cnn_model is None):
            raise RuntimeError(
                "AI inference is unavailable; provide a trained model and vectorizer in models/."
            )

        request_text = format_request_text(method, path, query)
        features = vectorizer.transform([request_text])
        rf_decision = None
        rf_confidence = None
        if model is not None:
            rf_decision = self._decision(model.predict(features)[0])
        if model is not None and self._supports_probabilities:
            probabilities = model.predict_proba(features)
            rf_confidence = float(max(probabilities[0]))

        dl_decision = None
        dl_confidence = None
        if cnn_model is not None:
            dense_features = features.toarray().astype("float32")
            cnn_input = dense_features.reshape(
                (dense_features.shape[0], dense_features.shape[1], 1)
            )
            probability = float(cnn_model.predict(cnn_input, verbose=0)[0][0])
            dl_decision = self._decision(int(probability >= 0.5))
            dl_confidence = probability if probability >= 0.5 else 1.0 - probability

        return AIPrediction(
            rf_decision=rf_decision,
            rf_confidence=rf_confidence,
            dl_decision=dl_decision,
            dl_confidence=dl_confidence,
        )
