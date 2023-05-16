import pandas as pd
import numpy as np
import math

# Define the filename and path of the dataset
filename = 'FlowStatsfile.csv'

# Load the dataset into a Pandas DataFrame
data = pd.read_csv(filename)

# Step 1: Calculate the parameters for entropy calculation
flow_rate = data['packet_count_per_second'].dropna()
flow_duration = data['flow_duration_sec'].dropna()
flow_size = data['byte_count'].dropna()
flow_length = data['packet_count'].dropna()

# Step 2: Calculate entropy for each parameter
def calculate_entropy(parameter, normalized=False):
    frequency = parameter.value_counts()
    n = 0
    entropy = 0
    
    for i, x in list(enumerate(frequency)):
        p_x = frequency.get(i, 0) / sum(frequency)
        if p_x > 0:
            n += 1
            entropy += -p_x * math.log(p_x, 2)
    
    if normalized:
        if math.log(n) > 0:
            normalized_ent = entropy / math.log(n, 2)
            return entropy, normalized_ent
        else:
            return entropy
    else:
        return entropy

entropy_flow_rate = calculate_entropy(flow_rate)
entropy_flow_duration = calculate_entropy(flow_duration)
entropy_flow_size = calculate_entropy(flow_size)
entropy_flow_length = calculate_entropy(flow_length)

# Step 3: Calculate entropy gain for each parameter
label_entropy = calculate_entropy(data['label'])
entropy_gain_flow_rate = entropy_flow_rate - (label_entropy * entropy_flow_rate)
entropy_gain_flow_duration = entropy_flow_duration - (label_entropy * entropy_flow_duration)
entropy_gain_flow_size = entropy_flow_size - (label_entropy * entropy_flow_size)
entropy_gain_flow_length = entropy_flow_length - (label_entropy * entropy_flow_length)

# Step 4: Calculate normalized entropy gain for each parameter
normalized_entropy_gain_flow_rate = entropy_gain_flow_rate / entropy_flow_rate
normalized_entropy_gain_flow_duration = entropy_gain_flow_duration / entropy_flow_duration
normalized_entropy_gain_flow_size = entropy_gain_flow_size / entropy_flow_size
normalized_entropy_gain_flow_length = entropy_gain_flow_length / entropy_flow_length

# Step 5: Calculate the degree of DDoS attack (DoD)
degree_of_ddos = (normalized_entropy_gain_flow_rate + normalized_entropy_gain_flow_duration +
                  normalized_entropy_gain_flow_size + normalized_entropy_gain_flow_length) / 4

# Step 6: Check if DDoS attack is detected
if degree_of_ddos > 0.5:
    print("DDoS attack detected!")
else:
    print("No DDoS attack detected.")

# Calculate accuracy
ground_truth_labels = data['label']
predicted_labels = ['DDoS attack detected' if dod > 0.5 else 'No DDoS attack detected' for dod in np.array([degree_of_ddos])]
accuracy = (ground_truth_labels == predicted_labels).mean()
print("Accuracy: {:.2%}".format(accuracy))

# Identify the rows where DDoS attack is detected
ddos_attack_rows = data[degree_of_ddos > 0.5]

# Print the IP address(es) of the attack
if not ddos_attack_rows.empty:
    attack_ip_addresses = ddos_attack_rows['ip_address']
    print("IP address(es) of the attack:")
    print(attack_ip_addresses.to_string(index=False))
else:
    print("No IP addresses associated with the attack.")
