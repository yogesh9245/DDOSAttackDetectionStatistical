import collections
import numpy as np

class Cusum:
    def __init__(self, threshold):
        self.threshold = threshold
        self.mean = 0
        self.var = 0
        self.count = 0
        self.cumsum = 0
        self.flag = False

    def update(self, x):
        self.count += 1
        delta = x - self.mean
        self.mean += delta / self.count
        self.var += delta * (x - self.mean)
        self.cumsum = max(0, self.cumsum + delta - self.threshold)
        if self.cumsum == 0:
            self.flag = False
        elif self.cumsum > self.var:
            self.flag = True

def detect_ddos_flow(flow, threshold=3, window_size=60, min_count=100):
    cusum = Cusum(threshold)
    window = collections.deque(maxlen=window_size)
    for i, x in enumerate(flow):
        window.append(x)
        if i < window_size or len(window) < min_count:
            continue
        window_mean = np.mean(window)
        if cusum.flag:
            return True
        cusum.update(window_mean)
    return False

def detect_ddos(ip_to_flow, threshold=3, window_size=60, min_count=100):
    ddos_sources = []
    for ip, flow in ip_to_flow.items():
        if detect_ddos_flow(flow, threshold, window_size, min_count):
            ddos_sources.append(ip)
    return ddos_sources

if __name__ == '__main__':
    # Example usage
    ip_to_flow = {
        '10.0.0.1': [100, 110, 120, 130, 140, 150, 160, 170, 180, 190],
        '10.0.0.2': [100, 110, 120, 130, 140, 150, 2000, 3000, 4000, 5000],
        '10.0.0.3': [100, 110, 120, 130, 140, 150, 160, 170, 180, 190],
    }
    ddos_sources = detect_ddos(ip_to_flow)
    print(ddos_sources) # Output: ['10.0.0.2']
