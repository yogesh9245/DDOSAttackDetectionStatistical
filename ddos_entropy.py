import pandas as pd
import numpy as np
from statsmodels.tsa.stattools import adfuller

# Load the dataset
dataset = pd.read_csv('FlowStatsfile.csv')

# Constants for entropy-based detection algorithm
window_size = 50
threshold = 1
consecutive_periods = 2

# Extract relevant columns for analysis
src_ips = dataset['ip_src']
dst_ips = dataset['ip_dst']

# Create a hash table of destination IP addresses and their occurrences
ip_hash_table = {}

# Function to calculate entropy
def entropy(payload):
    payload = str(payload)
    if len(payload) == 0:
        return 0
    entropy = 0
    for x in range(256):
        p_x = float(payload.count(chr(x))) / len(payload)
        if p_x > 0:
            entropy += - p_x * np.log2(p_x)
    return entropy

# Variables for tracking entropy and attack detection
entropies = []
entropy_window = []
attack_counter = 0

# Variables for augmented Dickey-Fuller test
adf_threshold = -0.45  # Adjust the threshold as per your requirement

# Iterate over the dataset
for i in range(len(dataset)):
    dst_ip = dst_ips[i]

    # Update the hash table for the destination IP address
    if dst_ip in ip_hash_table:
        ip_hash_table[dst_ip] += 1
    else:
        ip_hash_table[dst_ip] = 1

    # Remove the oldest entry from the hash table if the window size is exceeded
    if len(ip_hash_table) > window_size:
        oldest_ip = list(ip_hash_table.keys())[0]
        ip_hash_table.pop(oldest_ip)

    # Calculate the probability for each destination IP address in the window
    probabilities = [count / window_size for count in ip_hash_table.values()]

    # Calculate the entropy for the window
    current_entropy = entropy(probabilities)
    entropies.append(current_entropy)

    # Check if the entropy is below the threshold
    if current_entropy < threshold:
        # Perform augmented Dickey-Fuller test on entropies
        adf_result = adfuller(entropies)
        adf_statistic = adf_result[0]
        if adf_statistic < adf_threshold:
            attack_counter += 1
            if attack_counter == consecutive_periods:
                print('DDoS attack detected at index', i)
        else:
            attack_counter = 0
    else:
        attack_counter = 0

# Calculate the information gain
information_gain = np.mean(entropies)

print('Information Gain:', information_gain)
