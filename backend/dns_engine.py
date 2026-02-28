import os, re, joblib, math
import pandas as pd
from backend.config import *

class DNSEngine:
    def __init__(self):
        self.model = joblib.load(MODEL_FILE)
        self.top_domains = set()
        try:
            with open("top_1m.txt", "r") as f:
                self.top_domains = {line.strip() for line in f if line.strip()}
        except FileNotFoundError:
            print("Warning: top_1m.txt not found. Using empty set.")
            self.top_domains = {"google.com", "facebook.com"}

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

