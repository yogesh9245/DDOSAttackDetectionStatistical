import math
import numpy as np
from statsmodels.tsa.stattools import adfuller

def calculate_entropy(data, normalized=False):
    frequency = np.bincount(data)
    n = 0
    entropy = 0

    for i, x in enumerate(frequency):
        px = x / len(data)
        if px > 0:
            n += 1
            entropy += -px * math.log2(px)

    if normalized:
        if math.log2(n) > 0:
            normalized_ent = entropy / math.log2(n)
            return entropy, normalized_ent
    else:
        return entropy

def calculate_entropy_gain(entropy, constant, sum_entropy):
    entropy_gain = entropy - (constant * sum_entropy)
    return entropy_gain

def calculate_normalized_entropy_gain(entropy_gain, num_parameters):
    normalized_entropy_gain = entropy_gain / num_parameters
    return normalized_entropy_gain

def calculate_degree_of_ddos(entropy_gains, num_parameters):
    sum_normalized_entropy_gains = sum(entropy_gains)
    degree_of_ddos = sum_normalized_entropy_gains / num_parameters
    return degree_of_ddos

def detect_ddos_attack(data, significance_level=0.05):
    parameters = ['flow_rate', 'flow_size', 'flow_duration', 'flow_length']
    entropy_gains = []
    num_parameters = len(parameters)

    for parameter in parameters:
        entropy = calculate_entropy(data[parameter])
        entropy_gain = calculate_entropy_gain(entropy, 0.1, sum(entropy_gains))
        entropy_gains.append(entropy_gain)

    normalized_entropy_gains = [calculate_normalized_entropy_gain(eg, num_parameters) for eg in entropy_gains]
    degree_of_ddos = calculate_degree_of_ddos(normalized_entropy_gains, num_parameters)

    if degree_of_ddos > 0.5:
        # Perform augmented Dickey-Fuller test
        adf_result = adfuller(data['flow_size'], regression='n')

        if adf_result[1] < significance_level:
            return True

    return False

# Example usage
data = {
    'flow_rate': [10, 15, 12, 14, 13, 11, 9, 10, 10, 16],
    'flow_size': [50, 55, 60, 65, 70, 75, 80, 85, 90, 95],
    'flow_duration': [2, 4, 6, 8, 10, 12, 14, 16, 18, 20],
    'flow_length': [100, 200, 300, 400, 500, 600, 700, 800, 900, 1000]
}

is_ddos_attack = detect_ddos_attack(data)
if is_ddos_attack:
    print("DDoS attack detected!")
else:
    print("No DDoS attack detected.")
