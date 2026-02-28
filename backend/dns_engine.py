import os, re, joblib, math
import pandas as pd
from config import *

class DNSEngine:
    def __init__(self):
        self.model = joblib.load(MODEL_FILE)
        self.top_domains = set(
            pd.read_csv(TOP1M_FILE, header=None)[1].values
        )

    def entropy(self, s):
        prob = [float(s.count(c)) / len(s) for c in dict.fromkeys(list(s))]
        return -sum([p * math.log2(p) for p in prob])

    def extract_features(self, domain):
        return [
            len(domain),
            domain.count("."),
            sum(c.isdigit() for c in domain),
        ]
    
    def is_ip_address(self, domain):
        ip_pattern = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
        return re.match(ip_pattern, domain) is not None

    def ml_check(self, domain):
        malicious_extensions = [".sh", ".exe", ".bin", ".py", ".php"]
        if any(ext in domain.lower() for ext in malicious_extensions):
            return 1, 0.99
        if domain in self.top_domains:
            return 0, 0.0
        if self.is_ip_address(domain):
            return 1, 0.95

        features = [self.extract_features(domain)]
        pred = self.model.predict(features)[0]
        prob = self.model.predict_proba(features)[0][1]

        return pred, prob