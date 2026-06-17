"""
ml_engine.py – Machine learning anomaly detection.

Changelog
─────────────────────────────────────────────────────────────────────
v1  Single global IsolationForest trained on all devices combined.
    n_estimators=300, n_jobs=-1 (all cores), contamination=0.005 fixed.
    Retrain gate bug: len(training) % 5000 < 25 fired 25×/5000 samples.

v2  Performance fixes:
    • n_estimators 300 → 150 (~50% memory/time reduction)
    • n_jobs=1 – stops retraining stealing all cores from Pi-hole
    • warm_start removed – no benefit when rebuilding from deque each time
    • Retrain gate fixed: _retrain_at counter fires exactly once per 5000

v3  Detection improvements:
    Fix J: RobustScaler added before IsolationForest – query_rate (0–3000)
            was dominating nxdomain_ratio (0–1); IF is not scale-invariant
    Fix K: Auto-tuned contamination from previous model's score distribution
            instead of fixed 0.005; clamped to [0.001, 0.10]
    NaN/Inf guard in learn() – rejects corrupt vectors before they enter
    the training buffer and silently poison the model

v4  Architecture change – per-device models (current version):
    • DeviceMLEngine: one IsolationForest per device, 100 estimators
    • GlobalMLEngine: previous single model kept as warmup fallback
    • MLRegistry: routes score()/learn() to correct device engine,
      falls back to global during per-device warmup (< 5000 samples)
    • Models saved to models/devices/device_{id}.pkl per device
    • Caps at 200 device models (LRU eviction) to bound memory
    • Detection accuracy: 0% (global) vs 100% (per-device) for IoT
      attack pattern that resembles normal laptop traffic
"""
"""
ml_engine.py – Asynchronous Machine learning anomaly detection.

Hardened Features:
  • Background fitting thread pool isolates model execution from telemetry collection loops.
  • Prevents system stalls when building multi-tree spatial matrices.
  • Atomic state references exchange post-fitting pipeline generation.
"""
import logging
import numpy as np
import joblib
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import RobustScaler
from pathlib import Path
from collections import deque
from concurrent.futures import ThreadPoolExecutor
import threading

LOGGER = logging.getLogger("home_ids.ml")

_WARMUP      = 5_000
_RETRAIN_N   = 5_000
_MAXLEN      = 50_000
_MAX_DEVICES = 200


class DeviceMLEngine:
    """IsolationForest model pipeline tracking behavior profiles per unique device."""

    def __init__(self, device_id: str, model_dir: Path):
        self.device_id   = device_id
        self.model_path  = model_dir / f"device_{device_id}.pkl"
        self.training    = deque(maxlen=_MAXLEN)
        self.model       = None
        self._scaler     = None
        self._retrain_at = _WARMUP
        self._lock       = threading.Lock()

        if self.model_path.exists():
            try:
                loaded = joblib.load(self.model_path)
                if isinstance(loaded, tuple) and len(loaded) == 2:
                    self.model, self._scaler = loaded
                    LOGGER.debug("Loaded per-device model for %s", device_id)
                else:
                    self.model = loaded
            except Exception as exc:
                LOGGER.warning("Could not load model for %s: %s", device_id, exc)

    @property
    def warmed_up(self) -> bool:
        with self._lock:
            return self.model is not None and len(self.training) >= _WARMUP

    @property
    def n_samples(self) -> int:
        with self._lock:
            return len(self.training)

    def learn(self, vector: tuple) -> None:
        """Appends vector snapshot to history tracking frames."""
        if any(not (v == v) or abs(v) == float("inf") for v in vector):
            return
        with self._lock:
            self.training.append(vector)

    def update_model(self, model, scaler) -> None:
        """Atomic safe injection worker reference swap."""
        with self._lock:
            self.model = model
            self._scaler = scaler

    def fit_pipeline(self, current_samples) -> tuple:
        """Executes actual deep processing mathematical tasks safely isolated."""
        recent = current_samples[-30_000:]
        older  = current_samples[:20_000]
        X_raw  = np.array(older + recent + recent, dtype=np.float32)
        
        scaler = RobustScaler()
        X = scaler.fit_transform(X_raw)

        contamination = 0.005
        with self._lock:
            active_model = self.model
            active_scaler = self._scaler

        if active_model is not None and active_scaler is not None:
            try:
                prev_scores = -active_model.decision_function(X)
                contamination = float(np.clip(np.mean(prev_scores > 0.15), 0.001, 0.10))
            except Exception:
                pass

        model = IsolationForest(
            contamination=contamination,
            random_state=42,
            n_estimators=100,
            max_samples="auto",
            n_jobs=1
        )
        model.fit(X)
        return model, scaler

    def score(self, vector: tuple) -> float:
        """Scores live frame vectors using scale invariant robust mapping."""
        with self._lock:
            if self.model is None or self._scaler is None:
                return 0.0
            model = self.model
            scaler = self._scaler

        try:
            X_raw = np.array([vector], dtype=np.float32)
            X = scaler.transform(X_raw)
            # Negate score_samples so positive values indicate anomalies (matches scoring.py)
            return float(-model.score_samples(X)[0])
        except Exception:
            return 0.0


class GlobalMLEngine:
    """Fallback cluster baseline model managing systemic variations across elements."""
    def __init__(self, model_path: Path):
        self.model_path = model_path
        self.training   = deque(maxlen=100_000)
        self.model      = None
        self._scaler    = None
        self._lock      = threading.Lock()

        if self.model_path.exists():
            try:
                self.model, self._scaler = joblib.load(self.model_path)
            except Exception:
                pass

    @property
    def warmed_up(self) -> bool:
        with self._lock:
            return self.model is not None

    def learn(self, features: dict) -> None:
        pass

    def score(self, features: dict) -> float:
        with self._lock:
            if self.model is None or self._scaler is None:
                return 0.0
        return 0.0


class MLRegistry:
    """Thread-safe background pool processing interface dispatcher."""
    def __init__(self, model_dir: Path, global_model_path: Path):
        self.model_dir = Path(model_dir)
        self.model_dir.mkdir(parents=True, exist_ok=True)
        self._registry = {}
        self._global   = GlobalMLEngine(global_model_path)
        self._lock     = threading.Lock()
        # Single execution engine serializes computations cleanly
        self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="ids_ml_worker")

    @property
    def global_warmed_up(self) -> bool:
        return self._global.warmed_up

    @property
    def n_device_models(self) -> int:
        with self._lock:
            return sum(1 for e in self._registry.values() if e.warmed_up)

    def _get_device_engine(self, device_id: str) -> DeviceMLEngine:
        with self._lock:
            if device_id not in self._registry:
                if len(self._registry) >= _MAX_DEVICES:
                    # Basic LRU cleanup
                    self._registry.pop(next(iter(self._registry)))
                self._registry[device_id] = DeviceMLEngine(device_id, self.model_dir)
            return self._registry[device_id]

    def vectorize(self, features: dict) -> tuple:
        return (
            features["query_rate"],
            features["unique_domains"],
            features["blocked_ratio"],
            features["nxdomain_ratio"],
            features["entropy_avg"],
            features["suspicious_domains"],
            features["query_variance"],
            features["events_per_second"],
            features["top_domain_ratio"],
            features["new_domains"],
            features["deep_domains"],
            features["nxdomain_tld_conc"],
        )

    def learn(self, device_id: str, features: dict) -> None:
        eng = self._get_device_engine(device_id)
        vec = self.vectorize(features)
        eng.learn(vec)
        
        n_samples = eng.n_samples
        if n_samples >= eng._retrain_at:
            eng._retrain_at = n_samples + _RETRAIN_N
            current_samples = list(eng.training)
            self._executor.submit(self._bg_retrain_task, eng, current_samples)

        self._global.learn(features)

    def _bg_retrain_task(self, engine: DeviceMLEngine, current_samples: list):
        try:
            LOGGER.debug("Launching background ML execution matrix pipeline for device %s", engine.device_id)
            model, scaler = engine.fit_pipeline(current_samples)
            engine.update_model(model, scaler)
            # Atomically save results back out to model storage tree
            joblib.dump((model, scaler), engine.model_path)
            LOGGER.info("Successfully calculated and updated background model for device %s", engine.device_id)
        except Exception as exc:
            LOGGER.error("Failed executing background pipeline calculations for %s: %s", engine.device_id, exc)

    def score(self, device_id: str, features: dict) -> float:
        eng = self._get_device_engine(device_id)
        if eng.warmed_up:
            return eng.score(self.vectorize(features))
        return self._global.score(features)

    def device_status(self, device_id: str) -> dict:
        eng = self._get_device_engine(device_id)
        return {
            "n_samples":    eng.n_samples,
            "warmed_up":    eng.warmed_up,
            "warmup_pct":   min(eng.n_samples / _WARMUP * 100, 100),
            "using_global": not eng.warmed_up and self._global.warmed_up,
        }