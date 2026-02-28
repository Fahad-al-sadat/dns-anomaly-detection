import time
from collections import defaultdict
from config import *

class BehaviorEngine:
    def __init__(self):
        self.logs = defaultdict(list)

    def analyze(self, ip, domain):
        now = time.time()
        self.logs[ip].append((now, domain))

        # remove old
        self.logs[ip] = [
            (t, d) for t, d in self.logs[ip]
            if now - t <= TIME_WINDOW
        ]

        queries = self.logs[ip]
        rate = len(queries)
        unique_domains = len(set(d for _, d in queries))

        score = 0

        if rate > QUERY_RATE_THRESHOLD:
            score += 1
        if unique_domains > UNIQUE_DOMAIN_THRESHOLD:
            score += 1

        return score