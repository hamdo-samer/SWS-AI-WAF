import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from ai_engine import AIDetector


class _TestVectorizer:
    def __init__(self):
        self.values = None

    def transform(self, values):
        self.values = values
        return values


class _TestClassifier:
    def predict(self, features):
        return [1]

    def predict_proba(self, features):
        return [[0.15, 0.85]]


class AIDetectorTests(unittest.TestCase):
    def test_missing_model_files_are_reported_as_unavailable(self):
        with tempfile.TemporaryDirectory() as directory:
            detector = AIDetector(
                Path(directory) / "random_forest.joblib",
                Path(directory) / "vectorizer.joblib",
                Path(directory) / "1d_cnn.keras",
            )

            self.assertFalse(detector.is_available)
            with self.assertRaisesRegex(RuntimeError, "AI inference is unavailable"):
                detector.predict("GET", "/products")

    def test_configured_model_returns_its_label_and_confidence(self):
        with tempfile.TemporaryDirectory() as directory:
            model_path = Path(directory) / "random_forest.joblib"
            vectorizer_path = Path(directory) / "vectorizer.joblib"
            cnn_path = Path(directory) / "1d_cnn.keras"
            model_path.touch()
            vectorizer_path.touch()
            model = _TestClassifier()
            vectorizer = _TestVectorizer()

            def load(path):
                return {
                    model_path: model,
                    vectorizer_path: vectorizer,
                }[Path(path)]

            with patch("ai_engine.importlib.import_module") as import_module:
                import_module.return_value = SimpleNamespace(load=load)
                detector = AIDetector(model_path, vectorizer_path, cnn_path)

            prediction = detector.predict("GET", "/products", "category=books")

            self.assertTrue(detector.is_available)
            self.assertEqual(prediction.rf_decision, "Engellendi")
            self.assertEqual(prediction.rf_confidence, 0.85)
            self.assertIsNone(prediction.dl_decision)
            self.assertEqual(
                vectorizer.values,
                [
                    "Method: GET\nURL: /products?category=books\n"
                    "LEN:2 SPEC:0 SQL:0 JS:0"
                ],
            )

    def test_configured_cnn_returns_binary_decision_and_confidence(self):
        class DenseArray:
            shape = (1, 2)

            def astype(self, dtype):
                return self

            def reshape(self, shape):
                return self

        class SparseFeatures:
            shape = (1, 2)

            def toarray(self):
                return DenseArray()

        class CNNModel:
            def predict(self, features, verbose=0):
                return [[0.8]]

        class CNNVectorizer:
            def transform(self, values):
                return SparseFeatures()

        with tempfile.TemporaryDirectory() as directory:
            model_path = Path(directory) / "random_forest.joblib"
            vectorizer_path = Path(directory) / "vectorizer.joblib"
            cnn_path = Path(directory) / "1d_cnn.keras"
            vectorizer_path.touch()
            cnn_path.touch()
            vectorizer = CNNVectorizer()
            cnn_model = CNNModel()

            def import_module(name):
                if name == "joblib":
                    return SimpleNamespace(
                        load=lambda path: vectorizer if Path(path) == vectorizer_path else None
                    )
                if name == "tensorflow":
                    return SimpleNamespace(
                        keras=SimpleNamespace(
                            models=SimpleNamespace(
                                load_model=lambda path: cnn_model
                            )
                        )
                    )
                raise AssertionError(f"Unexpected optional dependency: {name}")

            with patch("ai_engine.importlib.import_module", side_effect=import_module):
                detector = AIDetector(model_path, vectorizer_path, cnn_path)

            prediction = detector.predict("GET", "/products")

            self.assertFalse(detector.rf_available)
            self.assertTrue(detector.dl_available)
            self.assertEqual(prediction.dl_decision, "Engellendi")
            self.assertEqual(prediction.dl_confidence, 0.8)


if __name__ == "__main__":
    unittest.main()
