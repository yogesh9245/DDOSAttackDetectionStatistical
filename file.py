import pandas as pd
import math
from statsmodels.tsa.stattools import adfuller

# Load the dataset
data = pd.read_csv("TFTP_mini.csv")
def calculate_entropy(data, normalized=True):
    frequency = data.value_counts()
    entropy = 0.0
    normalized_ent = 0.0
    n = 0

    for i, x in list(enumerate(frequency.index)):
        try:
            p_x = frequency[x] / sum(frequency)
            if p_x > 0:
                n += 1
                entropy += -p_x * math.log(p_x, 2)
        except KeyError:
            continue

    if normalized:
        if math.log(n) > 0:
            normalized_ent = entropy / math.log(n, 2)
            return entropy, normalized_ent
    else:
        return entropy

# Select relevant columns for analysis
columns = ["Timestamp", "Total Length of Fwd Packets", "Total Length of Bwd Packets","Flow Duration"]
selected_data = data[columns]

# Convert Timestamp column to datetime object
selected_data["Timestamp"] = pd.to_datetime(selected_data["Timestamp"])

# Sort the data by Timestamp
selected_data.sort_values(by="Timestamp", inplace=True)

# Convert Timestamp to Unix timestamps
numeric_time = selected_data["Timestamp"].apply(lambda x: x.timestamp())

# Perform ADF test on the numerical time data
result = adfuller(numeric_time)
p_value = result[1]

threshold = 0.05
print("ADF p-value:", p_value)

if p_value < threshold:
    print("DDoS attack detected.")
else:
    print("No DDoS attack detected.")
    
    # Additional steps for entropy calculation and detection
    flow_size = selected_data["Total Length of Fwd Packets"] + selected_data["Total Length of Bwd Packets"]
    flow_rate = flow_size / selected_data["Flow Duration"]
    flow_duration = selected_data["Flow Duration"]
    flow_length = selected_data["Total Length of Fwd Packets"] + selected_data["Total Length of Bwd Packets"]

    # Calculate entropy for each parameter
    entropy_flow_size, normalized_entropy_flow_size = calculate_entropy(flow_size)
    entropy_flow_rate, normalized_entropy_flow_rate = calculate_entropy(flow_rate)
    entropy_flow_duration, normalized_entropy_flow_duration = calculate_entropy(flow_duration)
    entropy_flow_length, normalized_entropy_flow_length = calculate_entropy(flow_length)
    
    print("Entropy (Flow Size):", entropy_flow_size)
    print("Normalized Entropy (Flow Size):", normalized_entropy_flow_size)
    print("Entropy (Flow Rate):", entropy_flow_rate)
    print("Normalized Entropy (Flow Rate):", normalized_entropy_flow_rate)
    print("Entropy (Flow Duration):", entropy_flow_duration)
    print("Normalized Entropy (Flow Duration):", normalized_entropy_flow_duration)
    print("Entropy (Flow Length):", entropy_flow_length)
    print("Normalized Entropy (Flow Length):", normalized_entropy_flow_length)
    
    # Calculate degree of DDoS attack
    degree_of_ddos = (normalized_entropy_flow_size + normalized_entropy_flow_rate +
                      normalized_entropy_flow_duration + normalized_entropy_flow_length) / 4
                      
    print("Degree of DDoS Attack:", degree_of_ddos)
    
    if degree_of_ddos > 0.5:
        print("DDoS attack detected.")
    else:
        print("No DDoS attack detected.")
    
