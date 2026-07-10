"""
ml_engine.py – Per-device IsolationForest with global fallback.

Bug fixes in this version:
  BUG 1 — warmed_up required model AND n_samples >= _WARMUP simultaneously.
           After a restart the model is loaded from disk but training deque
           is empty, so warmed_up was always False — model was loaded but
           never used. Fix: warmed_up = model is not None. The training
           deque fills up again in the background and triggers retraining
           when it hits _WARMUP samples, but the loaded model scores
           immediately on the very first cycle after restart.

  BUG 2 — retrain gate (_retrain_at) was read outside the lock while
           n_samples was read inside it — creating a window where a
           background retrain could double-submit. Fixed: a separate
           _retrain_pending flag prevents concurrent retrains.

  BUG 3 — GlobalMLEngine.learn() was a no-op and score() always returned
           0.0 even when a model was loaded from disk. During per-device
           warmup (< 5000 samples after restart) the ML signal was always
           0.0. Fixed: GlobalMLEngine is now a full working engine that
           trains on new data and scores correctly.

  BUG 4 — vectorize() used raw feature values (query_rate 0-3000,
           unique_domains 0-500) instead of z-scores. Per-device models
           should learn 'deviation from this device's baseline' — using
           z-scores makes the model device-agnostic and far more sensitive
           to actual anomalies. Raw values are still included for features
           that don't have z-scores (blocked_ratio, nxdomain_ratio, etc.).

  BUG 5 — fit_pipeline() read self.model/self._scaler under a lock then
           used them outside it. Fixed: snapshot both atomically, then
           use the snapshot outside the lock — safe against concurrent
           update_model() calls.
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

# _WARMUP must match ml_warmup_samples in config.json (both = 5000).
_WARMUP      = 5_000
_RETRAIN_N   = 5_000
# FIX 5: _MAXLEN reduced 50k→20k. 20k samples covers 4 full retrain cycles
# and keeps peak training memory at ~1.9 MB/device instead of ~4.8 MB.
# 20k × 12 features × 8 bytes = 1.9 MB per device.
_MAXLEN      = 20_000
# FIX 4: _MAX_DEVICES reduced 200→50. A home network has 10-30 devices.
# Worst case 50 devices × 1.9 MB = 95 MB, vs 200 × 4.8 MB = 960 MB.
_MAX_DEVICES = 50


# ── shared vectorizer ──────────────────────────────────────────────────────

def vectorize(features: dict) -> tuple:
    """
    Feature vector for IsolationForest.

    BUG 4 fix: z-score features used instead of raw values for the
    device-baseline-relative signals. A laptop at 80 q/min and an IoT
    device at 2 q/min have completely different raw values but both have
    z≈0 when behaving normally. The z-scores are already scaled to the
    device's own history, making the model device-type-agnostic.

    Raw ratios (blocked_ratio, nxdomain_ratio) kept as-is since they are
    already unit-normalised (0-1) and have semantic meaning without scaling.
    """
    return (
        # Device-relative z-scores — the primary anomaly signals
        float(features.get("query_rate_z",     0.0) or 0.0),
        float(features.get("entropy_z",        0.0) or 0.0),
        float(features.get("unique_domains_z", 0.0) or 0.0),
        float(features.get("nxdomain_z",       0.0) or 0.0),
        float(features.get("blocked_z",        0.0) or 0.0),
        float(features.get("dga_z",            0.0) or 0.0),
        # Unit-normalised absolute ratios
        float(features.get("blocked_ratio",    0.0) or 0.0),
        float(features.get("nxdomain_ratio",   0.0) or 0.0),
        float(features.get("top_domain_ratio", 0.0) or 0.0),
        float(features.get("entropy_avg",      0.0) or 0.0),
        # Structural signals
        float(features.get("new_domains",      0.0) or 0.0),
        float(features.get("deep_domains",     0.0) or 0.0),
    )


# ── per-device engine ──────────────────────────────────────────────────────

class DeviceMLEngine:
    """One IsolationForest trained only on this device's own traffic."""

    def __init__(self, device_id: str, model_dir: Path):
        self.device_id     = device_id
        self.model_path    = model_dir / f"device_{device_id}.pkl"
        self.training      = deque(maxlen=_MAXLEN)
        self.model         = None
        self._scaler       = None
        self._retrain_at   = _WARMUP
        self._retrain_pending = False   # BUG 2: prevent double-submit
        self._lock         = threading.Lock()

        # Load from disk — try .pkl then .tmp fallback
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
                    LOGGER.info("Loaded per-device model for %s from %s",
                                device_id, path.name)
                    break
                except Exception as exc:
                    LOGGER.warning("Could not load model for %s from %s: %s",
                                   device_id, path.name, exc)

    @property
    def warmed_up(self) -> bool:
        """
        BUG 1 fix: warmed_up = model is not None.

        Previously required BOTH (model is not None) AND (n_samples >= _WARMUP).
        After a restart the model was loaded from disk but training deque was
        empty — so warmed_up was False and the model was never used, forcing
        2.8 hours of re-warmup after every restart.

        Now: if a model exists (either loaded or just trained), it scores.
        The training deque fills in the background and triggers retraining
        at _WARMUP new samples, updating the model with fresh data.
        """
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
        """BUG 2 fix: atomic check of n_samples vs _retrain_at."""
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
            self.model   = model
            self._scaler = scaler

    def fit_pipeline(self, current_samples: list) -> tuple:
        """
        Train a new IsolationForest on current_samples.
        BUG 5 fix: snapshot model/scaler atomically then use outside lock.
        """
        recent = current_samples[-30_000:]
        older  = current_samples[:20_000]
        X_raw  = np.array(older + recent + recent, dtype=np.float32)

        scaler = RobustScaler()
        X      = scaler.fit_transform(X_raw)

        # BUG 5 fix: snapshot under lock, use snapshot outside
        with self._lock:
            snap_model  = self.model
            snap_scaler = self._scaler

        contamination = 0.005
        if snap_model is not None and snap_scaler is not None:
            try:
                prev_X      = snap_scaler.transform(X_raw)
                prev_scores = np.maximum(0.0, -snap_model.decision_function(prev_X))
                contamination = float(np.clip(
                    np.mean(prev_scores > 0.05), 0.001, 0.10
                ))
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
            snap_model  = self.model
            snap_scaler = self._scaler

        try:
            X_raw = np.array([vector], dtype=np.float32)
            X     = snap_scaler.transform(X_raw)
            return max(0.0, float(-snap_model.decision_function(X)[0]))
        except Exception:
            return 0.0

    def save_async(self, executor: ThreadPoolExecutor) -> None:
        """Save model to disk in background — atomic write via .tmp rename."""
        with self._lock:
            if self.model is None:
                return
            snap_model  = self.model
            snap_scaler = self._scaler

        path = self.model_path
        dev  = self.device_id

        def _save():
            try:
                path.parent.mkdir(parents=True, exist_ok=True)
                tmp = path.with_suffix(".tmp")
                joblib.dump((snap_model, snap_scaler), tmp, compress=3)
                tmp.replace(path)
                meta = {
                    "device_id":     dev,
                    "saved_at":      time.strftime("%Y-%m-%dT%H:%M:%S"),
                    "n_estimators":  snap_model.n_estimators,
                }
                path.with_suffix(".json").write_text(
                    json.dumps(meta, indent=2)
                )
                LOGGER.info("Saved model for %s", dev)
            except Exception as exc:
                LOGGER.warning("Could not save model for %s: %s", dev, exc)

        executor.submit(_save)


# ── global fallback engine ─────────────────────────────────────────────────

class GlobalMLEngine:
    """
    Single IsolationForest trained on all devices combined.
    Used as fallback while a per-device model warms up.

    BUG 3 fix: learn() now actually trains and score() now actually scores.
    Previously both were no-ops so the ML signal was always 0.0 until
    per-device warmup — which due to BUG 1 was also always 0.0 forever.
    """

    def __init__(self, model_path: Path):
        self.model_path  = Path(model_path)
        self.training    = deque(maxlen=100_000)
        self.model       = None
        self._scaler     = None
        self._retrain_at = _WARMUP
        self._retrain_pending = False
        self._lock       = threading.Lock()

        for path in (self.model_path, self.model_path.with_suffix(".tmp")):
            if path.exists():
                try:
                    loaded = joblib.load(path)
                    if isinstance(loaded, tuple) and len(loaded) == 2:
                        self.model, self._scaler = loaded
                    else:
                        self.model = loaded
                    LOGGER.info("Loaded global fallback model from %s", path.name)
                    break
                except Exception as exc:
                    LOGGER.warning("Could not load global model from %s: %s",
                                   path.name, exc)

    @property
    def warmed_up(self) -> bool:
        # BUG 1 fix (same as DeviceMLEngine): loaded model = ready to score
        with self._lock:
            return self.model is not None

    def learn(self, vector: tuple) -> None:
        """BUG 3 fix: actually append to training buffer."""
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
        """Train a new global model synchronously (called from background thread)."""
        with self._lock:
            samples     = list(self.training)
            snap_model  = self.model
            snap_scaler = self._scaler

        if len(samples) < 100:
            return

        recent = samples[-30_000:]
        older  = samples[:20_000]
        X_raw  = np.array(older + recent + recent, dtype=np.float32)

        scaler = RobustScaler()
        X      = scaler.fit_transform(X_raw)

        contamination = 0.005
        if snap_model is not None and snap_scaler is not None:
            try:
                prev_X      = snap_scaler.transform(X_raw)
                prev_scores = np.maximum(0.0, -snap_model.decision_function(prev_X))
                contamination = float(np.clip(np.mean(prev_scores > 0.05), 0.001, 0.10))
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
            self.model   = model
            self._scaler = scaler

        # Atomic save
        try:
            self.model_path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.model_path.with_suffix(".tmp")
            joblib.dump((model, scaler), tmp, compress=3)
            tmp.replace(self.model_path)
            LOGGER.info("Saved global model (%d samples)", len(samples))
        except Exception as exc:
            LOGGER.warning("Could not save global model: %s", exc)

    def score(self, vector: tuple) -> float:
        """BUG 3 fix: actually return a score when model is available."""
        with self._lock:
            if self.model is None or self._scaler is None:
                return 0.0
            snap_model  = self.model
            snap_scaler = self._scaler

        try:
            X_raw = np.array([vector], dtype=np.float32)
            X     = snap_scaler.transform(X_raw)
            return max(0.0, float(-snap_model.decision_function(X)[0]))
        except Exception:
            return 0.0


# ── registry ───────────────────────────────────────────────────────────────

class MLRegistry:
    """
    Unified interface used by main.py.

        ml.score(device_id, features) → float
        ml.learn(device_id, features) → None
        ml.global_warmed_up            → bool
        ml.n_device_models             → int
    """

    def __init__(self, model_dir: Path, global_model_path: Path):
        self.model_dir = Path(model_dir)
        self.model_dir.mkdir(parents=True, exist_ok=True)
        self._devices: dict[str, DeviceMLEngine] = {}
        self._global  = GlobalMLEngine(Path(global_model_path))
        self._lock    = threading.Lock()
        # Single-worker executor: serialises all background retrains so they
        # never compete for CPU with the scoring loop or each other.
        self._executor = ThreadPoolExecutor(
            max_workers=1, thread_name_prefix="ids_ml"
        )

    # ── internal ───────────────────────────────────────────────────────────

    def _get(self, device_id: str) -> DeviceMLEngine:
        with self._lock:
            if device_id not in self._devices:
                if len(self._devices) >= _MAX_DEVICES:
                    evict = next(iter(self._devices))
                    del self._devices[evict]
                self._devices[device_id] = DeviceMLEngine(
                    device_id, self.model_dir
                )
            return self._devices[device_id]

    def _bg_retrain(self, eng: DeviceMLEngine, samples: list) -> None:
        try:
            model, scaler = eng.fit_pipeline(samples)
            eng.update_model(model, scaler)
            eng.save_async(self._executor)
            LOGGER.info("Retrained per-device model for %s (%d samples)",
                        eng.device_id, len(samples))
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

    # ── public interface ───────────────────────────────────────────────────

    def learn(self, device_id: str, features: dict) -> None:
        vec = vectorize(features)

        # Per-device
        eng = self._get(device_id)
        eng.learn(vec)
        if eng.needs_retrain():
            samples = list(eng.training)
            self._executor.submit(self._bg_retrain, eng, samples)

        # Global fallback
        self._global.learn(vec)
        if self._global.needs_retrain():
            self._executor.submit(self._bg_global_retrain)

    def score(self, device_id: str, features: dict) -> float:
        vec = vectorize(features)
        eng = self._get(device_id)
        # BUG 1 fix: per-device scores immediately if model exists on disk
        if eng.warmed_up:
            return eng.score(vec)
        # Fallback to global (also scores immediately if model loaded from disk)
        return self._global.score(vec)

    def device_status(self, device_id: str) -> dict:
        eng = self._get(device_id)
        return {
            "n_samples":    eng.n_samples,
            "warmed_up":    eng.warmed_up,
            "warmup_pct":   min(eng.n_samples / _WARMUP * 100, 100),
            "using_global": not eng.warmed_up and self._global.warmed_up,
        }

    @property
    def global_warmed_up(self) -> bool:
        return self._global.warmed_up

    @property
    def n_device_models(self) -> int:
        with self._lock:
            return sum(1 for e in self._devices.values() if e.warmed_up)
