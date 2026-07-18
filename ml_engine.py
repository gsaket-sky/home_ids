"""
ml_engine.py – Per-device IsolationForest with global fallback.
Applies unsupervised machine learning models to detect stealthy deviations 
in standard network traffic behavior that evade typical human-set heuristics.

RECENT FIXES:
- Enforced a strict 0.05 contamination ceiling to prevent active-infection baseline poisoning.
- Hardened model fitting pipelines against NaN value injections.
"""

import json
import logging
import threading
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import RobustScaler

LOGGER = logging.getLogger("home_ids.ml")

_WARMUP = 5000
_RETRAIN_N = 5000
_MAXLEN = 20000
_MAX_DEVICES = 50

def vectorize(features: dict) -> tuple:
    """
    Constructs the feature vector for IsolationForest evaluation.
    Relies on structural Z-scores to remain device-type agnostic.
    """
    return (
        float(features.get("query_rate_z", 0.0) or 0.0),
        float(features.get("entropy_z", 0.0) or 0.0),
        float(features.get("unique_domains_z", 0.0) or 0.0),
        float(features.get("nxdomain_z", 0.0) or 0.0),
        float(features.get("blocked_z", 0.0) or 0.0),
        float(features.get("dga_z", 0.0) or 0.0),
        float(features.get("blocked_ratio", 0.0) or 0.0),
        float(features.get("nxdomain_ratio", 0.0) or 0.0),
        float(features.get("top_domain_ratio", 0.0) or 0.0),
        float(features.get("entropy_avg", 0.0) or 0.0),
        float(features.get("new_domains", 0.0) or 0.0),
        float(features.get("deep_domains", 0.0) or 0.0),
    )

class DeviceMLEngine:
    """Manages training and prediction for an individual device profile."""
    def __init__(self, device_id: str, model_dir: Path):
        self.device_id = device_id
        self.model_path = model_dir / f"device_{device_id}.pkl"
        self.training = deque(maxlen=_MAXLEN)
        self.model = None
        self._scaler = None
        self._retrain_at = _WARMUP
        self._retrain_pending = False
        self._lock = threading.Lock()

        for path in (self.model_path, self.model_path.with_suffix(".tmp")):
            if path.exists():
                try:
                    loaded = joblib.load(path)
                    if isinstance(loaded, tuple) and len(loaded) == 2:
                        self.model, self._scaler = loaded
                    elif isinstance(loaded, tuple) and len(loaded) == 1:
                        self.model = loaded[0]
                    else:
                        self.model = loaded
                    LOGGER.info("Loaded per-device model for %s", device_id)
                    break
                except Exception as exc:
                    LOGGER.warning("Could not load model for %s: %s", device_id, exc)

    @property
    def warmed_up(self) -> bool:
        with self._lock:
            return self.model is not None

    @property
    def n_samples(self) -> int:
        with self._lock:
            return len(self.training)

    def learn(self, vector: tuple) -> None:
        if any(v != v or abs(v) == float("inf") for v in vector):
            return
        with self._lock:
            self.training.append(vector)

    def needs_retrain(self) -> bool:
        with self._lock:
            if self._retrain_pending:
                return False
            if len(self.training) >= self._retrain_at:
                self._retrain_pending = True
                self._retrain_at = len(self.training) + _RETRAIN_N
                return True
            return False

    def retrain_complete(self) -> None:
        with self._lock:
            self._retrain_pending = False

    def update_model(self, model, scaler) -> None:
        with self._lock:
            self.model = model
            self._scaler = scaler

    def fit_pipeline(self, current_samples: list) -> tuple:
        LOGGER.debug("Starting pipeline fit for device %s", self.device_id)
        recent = current_samples[-30000:]
        older = current_samples[:20000]
        X_raw = np.array(older + recent + recent, dtype=np.float32)

        scaler = RobustScaler()
        X = scaler.fit_transform(X_raw)

        with self._lock:
            snap_model = self.model
            snap_scaler = self._scaler

        contamination = 0.005
        if snap_model is not None and snap_scaler is not None:
            try:
                prev_X = snap_scaler.transform(X_raw)
                if not np.isnan(prev_X).any():
                    prev_scores = np.maximum(0.0, -snap_model.decision_function(prev_X))
                    # FIX: Cap ceiling at 5% (0.05) strictly to prevent active-infection poisoning
                    contamination = float(np.clip(np.mean(prev_scores > 0.05), 0.001, 0.05))
            except Exception:
                pass

        model = IsolationForest(
            contamination=contamination,
            random_state=42,
            n_estimators=100,
            max_samples="auto",
            n_jobs=1,
        )
        model.fit(X)
        return model, scaler

    def score(self, vector: tuple) -> float:
        with self._lock:
            if self.model is None or self._scaler is None:
                return 0.0
            snap_model = self.model
            snap_scaler = self._scaler

        try:
            X_raw = np.array([vector], dtype=np.float32)
            X = snap_scaler.transform(X_raw)
            if np.isnan(X).any(): return 0.0
            score = max(0.0, float(-snap_model.decision_function(X)[0]))
            return score
        except Exception:
            return 0.0

    def save_async(self, executor: ThreadPoolExecutor) -> None:
        with self._lock:
            if self.model is None:
                return
            snap_model = self.model
            snap_scaler = self._scaler

        path = self.model_path
        dev = self.device_id

        def _save():
            try:
                path.parent.mkdir(parents=True, exist_ok=True)
                tmp = path.with_suffix(".tmp")
                joblib.dump((snap_model, snap_scaler), tmp, compress=3)
                tmp.replace(path)
                meta = {
                    "device_id": dev,
                    "saved_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
                    "n_estimators": snap_model.n_estimators,
                }
                path.with_suffix(".json").write_text(json.dumps(meta, indent=2))
            except Exception as exc:
                LOGGER.warning("Could not save model for %s: %s", dev, exc)

        executor.submit(_save)

class GlobalMLEngine:
    """Fallback IsolationForest model trained concurrently on the entire network cluster."""
    def __init__(self, model_path: Path):
        self.model_path = Path(model_path)
        self.training = deque(maxlen=100000)
        self.model = None
        self._scaler = None
        self._retrain_at = _WARMUP
        self._retrain_pending = False
        self._lock = threading.Lock()

        for path in (self.model_path, self.model_path.with_suffix(".tmp")):
            if path.exists():
                try:
                    loaded = joblib.load(path)
                    if isinstance(loaded, tuple) and len(loaded) == 2:
                        self.model, self._scaler = loaded
                    else:
                        self.model = loaded
                    LOGGER.info("Loaded global fallback model")
                    break
                except Exception as exc:
                    LOGGER.warning("Could not load global model: %s", exc)

    @property
    def warmed_up(self) -> bool:
        with self._lock:
            return self.model is not None

    def learn(self, vector: tuple) -> None:
        if any(v != v or abs(v) == float("inf") for v in vector):
            return
        with self._lock:
            self.training.append(vector)

    def needs_retrain(self) -> bool:
        with self._lock:
            if self._retrain_pending:
                return False
            if len(self.training) >= self._retrain_at:
                self._retrain_pending = True
                self._retrain_at = len(self.training) + _RETRAIN_N
                return True
            return False

    def retrain_complete(self) -> None:
        with self._lock:
            self._retrain_pending = False

    def fit_and_update(self) -> None:
        with self._lock:
            samples = list(self.training)
            snap_model = self.model
            snap_scaler = self._scaler

        if len(samples) < 100:
            return

        LOGGER.info("Initiating Global ML model fit with %d samples", len(samples))
        recent = samples[-30000:]
        older = samples[:20000]
        X_raw = np.array(older + recent + recent, dtype=np.float32)

        scaler = RobustScaler()
        X = scaler.fit_transform(X_raw)

        contamination = 0.005
        if snap_model is not None and snap_scaler is not None:
            try:
                prev_X = snap_scaler.transform(X_raw)
                if not np.isnan(prev_X).any():
                    prev_scores = np.maximum(0.0, -snap_model.decision_function(prev_X))
                    # FIX: Strict ceiling
                    contamination = float(np.clip(np.mean(prev_scores > 0.05), 0.001, 0.05))
            except Exception:
                pass

        model = IsolationForest(
            contamination=contamination,
            random_state=42,
            n_estimators=150,
            max_samples="auto",
            n_jobs=1,
        )
        model.fit(X)

        with self._lock:
            self.model = model
            self._scaler = scaler

        try:
            self.model_path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.model_path.with_suffix(".tmp")
            joblib.dump((model, scaler), tmp, compress=3)
            tmp.replace(self.model_path)
            LOGGER.info("Saved global model (%d samples)", len(samples))
        except Exception as exc:
            LOGGER.warning("Could not save global model: %s", exc)

    def score(self, vector: tuple) -> float:
        with self._lock:
            if self.model is None or self._scaler is None:
                return 0.0
            snap_model = self.model
            snap_scaler = self._scaler

        try:
            X_raw = np.array([vector], dtype=np.float32)
            X = snap_scaler.transform(X_raw)
            if np.isnan(X).any(): return 0.0
            return max(0.0, float(-snap_model.decision_function(X)[0]))
        except Exception:
            return 0.0

class MLRegistry:
    """Unified ML distribution interface mapping device hashes to isolation matrices."""
    def __init__(self, model_dir: Path, global_model_path: Path):
        self.model_dir = Path(model_dir)
        self.model_dir.mkdir(parents=True, exist_ok=True)
        self._devices = {}
        self._global = GlobalMLEngine(Path(global_model_path))
        self._lock = threading.Lock()
        self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="ids_ml")

    def _get(self, device_id: str) -> DeviceMLEngine:
        with self._lock:
            if device_id not in self._devices:
                if len(self._devices) >= _MAX_DEVICES:
                    evict = next(iter(self._devices))
                    del self._devices[evict]
                self._devices[device_id] = DeviceMLEngine(device_id, self.model_dir)
            return self._devices[device_id]

    def _bg_retrain(self, eng: DeviceMLEngine, samples: list) -> None:
        try:
            model, scaler = eng.fit_pipeline(samples)
            eng.update_model(model, scaler)
            eng.save_async(self._executor)
            LOGGER.info("Retrained per-device model for %s", eng.device_id)
        except Exception as exc:
            LOGGER.error("Retrain failed for %s: %s", eng.device_id, exc)
        finally:
            eng.retrain_complete()

    def _bg_global_retrain(self) -> None:
        try:
            self._global.fit_and_update()
        except Exception as exc:
            LOGGER.error("Global retrain failed: %s", exc)
        finally:
            self._global.retrain_complete()

    def learn(self, device_id: str, features: dict) -> None:
        vec = vectorize(features)

        eng = self._get(device_id)
        eng.learn(vec)
        if eng.needs_retrain():
            samples = list(eng.training)
            self._executor.submit(self._bg_retrain, eng, samples)

        self._global.learn(vec)
        if self._global.needs_retrain():
            self._executor.submit(self._bg_global_retrain)

    def score(self, device_id: str, features: dict) -> float:
        vec = vectorize(features)
        eng = self._get(device_id)
        if eng.warmed_up:
            return eng.score(vec)
        return self._global.score(vec)

    @property
    def global_warmed_up(self) -> bool:
        return self._global.warmed_up

    @property
    def n_device_models(self) -> int:
        with self._lock:
            return sum(1 for e in self._devices.values() if e.warmed_up)