import csv
import tempfile
import unittest
from pathlib import Path

import numpy as np

from train_models import _deduplicate_requests, load_dataset


class TrainingDataTests(unittest.TestCase):
    def test_duplicate_requests_are_deduplicated_and_conflicting_labels_excluded(self):
        texts, labels, conflicting_count = _deduplicate_requests(
            ["same", "same", "normal", "attack"],
            np.asarray([0, 0, 0, 1], dtype=np.int32),
        )
        self.assertEqual(texts, ["same", "normal", "attack"])
        self.assertEqual(labels.tolist(), [0, 0, 1])
        self.assertEqual(conflicting_count, 0)

        texts, labels, conflicting_count = _deduplicate_requests(
            ["same", "same", "normal", "attack"],
            np.asarray([0, 1, 0, 1], dtype=np.int32),
        )
        self.assertEqual(texts, ["normal", "attack"])
        self.assertEqual(labels.tolist(), [0, 1])
        self.assertEqual(conflicting_count, 1)

    def test_csv_loader_excludes_labels_from_request_text(self):
        with tempfile.TemporaryDirectory() as directory:
            dataset = Path(directory) / "csic.csv"
            with dataset.open("w", encoding="utf-8", newline="") as output:
                writer = csv.DictWriter(
                    output,
                    fieldnames=(
                        "classification",
                        "Method",
                        "User-Agent",
                        "Pragma",
                        "URL",
                    ),
                )
                writer.writeheader()
                writer.writerow({
                    "classification": "0",
                    "Method": "GET",
                    "User-Agent": "Browser/1",
                    "Pragma": "no-cache",
                    "URL": "http://localhost:8080/products?category=books HTTP/1.1",
                })
                writer.writerow({
                    "classification": "1",
                    "Method": "POST",
                    "User-Agent": "Browser/2",
                    "Pragma": "no-cache",
                    "URL": "/login",
                })

            texts, labels = load_dataset(dataset)

            self.assertEqual(labels.tolist(), [0, 1])
            self.assertEqual(
                texts[0],
                "Method: GET\nURL: /products?category=books\n"
                "LEN:2 SPEC:0 SQL:0 JS:0",
            )
            self.assertNotIn("Pragma", texts[0])
            self.assertNotIn("User-Agent", texts[0])
            self.assertNotIn("classification", texts[0])


if __name__ == "__main__":
    unittest.main()
