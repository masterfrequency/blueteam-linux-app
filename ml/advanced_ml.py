"""
BlueTeam Enterprise - Advanced ML Threat Detection
Anomaly detection, behavioral analysis, predictive threat scoring
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA
from sklearn.cluster import DBSCAN
import joblib
from typing import Dict, List, Tuple, Any
from datetime import datetime, timedelta
import logging

logger = logging.getLogger(__name__)


class AnomalyDetector:
    """Detect anomalies using Isolation Forest"""
    
    def __init__(self, contamination=0.1):
        self.model = IsolationForest(contamination=contamination, random_state=42)
        self.scaler = StandardScaler()
        self.is_trained = False
    
    def train(self, data: np.ndarray):
        """Train anomaly detector"""
        try:
            scaled_data = self.scaler.fit_transform(data)
            self.model.fit(scaled_data)
            self.is_trained = True
            logger.info("✓ Anomaly detector trained")
        except Exception as e:
            logger.error(f"Training error: {e}")
    
    def predict(self, data: np.ndarray) -> List[int]:
        """Predict anomalies (-1 for anomaly, 1 for normal)"""
        if not self.is_trained:
            return [1] * len(data)
        
        try:
            scaled_data = self.scaler.transform(data)
            return self.model.predict(scaled_data).tolist()
        except Exception as e:
            logger.error(f"Prediction error: {e}")
            return [1] * len(data)
    
    def get_anomaly_scores(self, data: np.ndarray) -> List[float]:
        """Get anomaly scores (higher = more anomalous)"""
        if not self.is_trained:
            return [0.0] * len(data)
        
        try:
            scaled_data = self.scaler.transform(data)
            return (-self.model.score_samples(scaled_data)).tolist()
        except Exception as e:
            logger.error(f"Scoring error: {e}")
            return [0.0] * len(data)


class BehavioralAnalyzer:
    """Analyze behavioral patterns for threat detection"""
    
    def __init__(self):
        self.baseline_profiles = {}
        self.deviation_threshold = 2.0  # Standard deviations
    
    def create_baseline(self, user_id: str, behavior_data: Dict[str, List[float]]):
        """Create baseline behavior profile"""
        profile = {}
        for metric, values in behavior_data.items():
            profile[metric] = {
                "mean": np.mean(values),
                "std": np.std(values),
                "min": np.min(values),
                "max": np.max(values)
            }
        self.baseline_profiles[user_id] = profile
        logger.info(f"✓ Baseline created for user {user_id}")
    
    def detect_deviation(self, user_id: str, current_behavior: Dict[str, float]) -> Tuple[bool, float]:
        """Detect behavioral deviations"""
        if user_id not in self.baseline_profiles:
            return False, 0.0
        
        baseline = self.baseline_profiles[user_id]
        max_deviation = 0.0
        
        for metric, value in current_behavior.items():
            if metric not in baseline:
                continue
            
            mean = baseline[metric]["mean"]
            std = baseline[metric]["std"]
            
            if std == 0:
                continue
            
            deviation = abs((value - mean) / std)
            max_deviation = max(max_deviation, deviation)
        
        is_anomaly = max_deviation > self.deviation_threshold
        return is_anomaly, max_deviation
    
    def get_risk_score(self, deviations: List[float]) -> float:
        """Calculate risk score from deviations"""
        if not deviations:
            return 0.0
        
        avg_deviation = np.mean(deviations)
        max_deviation = np.max(deviations)
        
        # Risk score: 0-100
        risk = min(100.0, (avg_deviation * 10 + max_deviation * 5) / 2)
        return risk


class ThreatPredictor:
    """Predict threats using Random Forest"""
    
    def __init__(self):
        self.model = RandomForestClassifier(n_estimators=100, random_state=42)
        self.feature_names = []
        self.is_trained = False
    
    def train(self, X: np.ndarray, y: np.ndarray, feature_names: List[str]):
        """Train threat predictor"""
        try:
            self.feature_names = feature_names
            self.model.fit(X, y)
            self.is_trained = True
            
            # Log feature importance
            importances = self.model.feature_importances_
            for name, importance in zip(feature_names, importances):
                logger.info(f"  {name}: {importance:.4f}")
            
            logger.info("✓ Threat predictor trained")
        except Exception as e:
            logger.error(f"Training error: {e}")
    
    def predict_threat_probability(self, features: np.ndarray) -> List[float]:
        """Predict threat probability"""
        if not self.is_trained:
            return [0.0] * len(features)
        
        try:
            probabilities = self.model.predict_proba(features)
            return probabilities[:, 1].tolist()  # Probability of threat class
        except Exception as e:
            logger.error(f"Prediction error: {e}")
            return [0.0] * len(features)
    
    def get_feature_importance(self) -> Dict[str, float]:
        """Get feature importance scores"""
        if not self.is_trained:
            return {}
        
        return {
            name: float(importance)
            for name, importance in zip(self.feature_names, self.model.feature_importances_)
        }


class ClusteringAnalyzer:
    """Detect threat clusters using DBSCAN"""
    
    def __init__(self, eps=0.5, min_samples=5):
        self.model = DBSCAN(eps=eps, min_samples=min_samples)
        self.scaler = StandardScaler()
    
    def find_clusters(self, data: np.ndarray) -> Tuple[np.ndarray, int]:
        """Find threat clusters"""
        try:
            scaled_data = self.scaler.fit_transform(data)
            labels = self.model.fit_predict(scaled_data)
            n_clusters = len(set(labels)) - (1 if -1 in labels else 0)
            return labels, n_clusters
        except Exception as e:
            logger.error(f"Clustering error: {e}")
            return np.array([]), 0


class PredictiveAnalytics:
    """Predictive analytics for threat forecasting"""
    
    def __init__(self):
        self.pca = PCA(n_components=0.95)
        self.history = []
    
    def reduce_dimensions(self, data: np.ndarray) -> np.ndarray:
        """Reduce data dimensions using PCA"""
        try:
            return self.pca.fit_transform(data)
        except Exception as e:
            logger.error(f"PCA error: {e}")
            return data
    
    def forecast_threats(self, historical_data: List[Dict]) -> Dict[str, Any]:
        """Forecast future threats"""
        if len(historical_data) < 10:
            return {"forecast": None, "confidence": 0.0}
        
        try:
            # Extract threat counts over time
            threat_counts = [d.get("count", 0) for d in historical_data[-30:]]
            
            # Simple trend analysis
            if len(threat_counts) > 1:
                trend = np.polyfit(range(len(threat_counts)), threat_counts, 1)[0]
                avg_count = np.mean(threat_counts)
                std_count = np.std(threat_counts)
                
                # Forecast next period
                forecast = avg_count + trend
                confidence = 1.0 - (std_count / (avg_count + 1))
                
                return {
                    "forecast": max(0, forecast),
                    "confidence": min(1.0, max(0.0, confidence)),
                    "trend": trend,
                    "average": avg_count
                }
        except Exception as e:
            logger.error(f"Forecast error: {e}")
        
        return {"forecast": None, "confidence": 0.0}


class MLThreatEngine:
    """Main ML threat detection engine"""
    
    def __init__(self):
        self.anomaly_detector = AnomalyDetector()
        self.behavioral_analyzer = BehavioralAnalyzer()
        self.threat_predictor = ThreatPredictor()
        self.clustering_analyzer = ClusteringAnalyzer()
        self.predictive_analytics = PredictiveAnalytics()
        self.threat_history = []
    
    def analyze_threat(self, threat_data: Dict[str, Any]) -> Dict[str, Any]:
        """Comprehensive threat analysis"""
        
        analysis = {
            "timestamp": datetime.utcnow().isoformat(),
            "threat_id": threat_data.get("id"),
            "threat_type": threat_data.get("type"),
            "scores": {}
        }
        
        # Anomaly score
        if "metrics" in threat_data:
            metrics = np.array([threat_data["metrics"]])
            anomaly_scores = self.anomaly_detector.get_anomaly_scores(metrics)
            analysis["scores"]["anomaly"] = float(anomaly_scores[0])
        
        # Behavioral score
        if "user_id" in threat_data and "behavior" in threat_data:
            is_anomaly, deviation = self.behavioral_analyzer.detect_deviation(
                threat_data["user_id"],
                threat_data["behavior"]
            )
            analysis["scores"]["behavioral"] = float(deviation)
            analysis["is_behavioral_anomaly"] = is_anomaly
        
        # Threat prediction
        if "features" in threat_data:
            features = np.array([threat_data["features"]])
            probabilities = self.threat_predictor.predict_threat_probability(features)
            analysis["scores"]["threat_probability"] = float(probabilities[0])
        
        # Calculate overall risk score
        scores = list(analysis["scores"].values())
        if scores:
            analysis["overall_risk_score"] = float(np.mean(scores)) * 100
        else:
            analysis["overall_risk_score"] = 0.0
        
        # Store in history
        self.threat_history.append(analysis)
        
        return analysis
    
    def save_model(self, path: str):
        """Save trained models"""
        try:
            joblib.dump(self.anomaly_detector, f"{path}/anomaly_detector.pkl")
            joblib.dump(self.threat_predictor, f"{path}/threat_predictor.pkl")
            logger.info(f"✓ Models saved to {path}")
        except Exception as e:
            logger.error(f"Save error: {e}")
    
    def load_model(self, path: str):
        """Load trained models"""
        try:
            self.anomaly_detector = joblib.load(f"{path}/anomaly_detector.pkl")
            self.threat_predictor = joblib.load(f"{path}/threat_predictor.pkl")
            logger.info(f"✓ Models loaded from {path}")
        except Exception as e:
            logger.error(f"Load error: {e}")


# Global ML engine
ml_engine = MLThreatEngine()
