"""Behavioral drift detection over rooted authority traces."""

# The persisted, unchanged joblib model names module4.detector.TrainedDetector.
# Keep that historical pickle import resolvable without retaining a second package.
import sys
from . import detector

sys.modules.setdefault("module4", sys.modules[__name__])
sys.modules.setdefault("module4.detector", detector)
