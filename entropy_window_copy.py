import pandas as pd
import numpy as np
import math

# Define the filename and path of the dataset
filename = 'FlowStatsfile.csv'
num = 0
# Load the dataset into a Pandas DataFrame
data = pd.read_csv(filename)
# print(data.columns)
# Step 1: Extract necessary columns from the dataset
selected_columns = ['timestamp', 'flow_duration_sec', 'packet_count_per_second', 'byte_count', 'ip_src']
data = data[selected_columns]

num2 = len(data)
# Step 2: Define the window size
window_size = 50

# Step 3: Define a function to calculate entropy
def calculate_entropy(parameter):
    frequency = parameter.value_counts()
    n = len(frequency)
    entropy = 0
    
    for x in frequency:
        p_x = x / n
        if p_x > 0:
            entropy += -p_x * math.log2(p_x)
    
    return entropy

# Step 4: Define a function to detect DDoS attacks using entropy analysis
def detect_ddos_attacks(data):
    num_windows = len(data) // window_size
    attack_windows = []
    
    for i in range(num_windows):
        # Extract a window of data
        start_index = i * window_size
        end_index = start_index + window_size
        window_data = data.iloc[start_index:end_index,:]
        
        # Step 5: Calculate the parameters for entropy calculation
        flow_rate = window_data['packet_count_per_second'].dropna()
        flow_duration = window_data['flow_duration_sec'].dropna()
        flow_size = window_data['byte_count'].dropna()
        
        # Step 6: Calculate entropy for each parameter
        entropy_flow_rate = calculate_entropy(flow_rate)
        entropy_flow_duration = calculate_entropy(flow_duration)
        entropy_flow_size = calculate_entropy(flow_size)
        
        # Step 7: Calculate the degree of DDoS attack (DoD)
        degree_of_ddos = (entropy_flow_rate + entropy_flow_duration +
                          entropy_flow_size) / 3
        
        # Step 8: Check if DDoS attack is detected
        if degree_of_ddos > 0.5:
            print()
            ip_src_values = window_data['ip_src'].str.strip().unique().tolist()
            attack_windows.append((start_index, end_index, ip_src_values))
    
    return attack_windows


# Step 9: Call the function to detect DDoS attacks
attack_windows = detect_ddos_attacks(data)

# Step 10: Print the detected attack windows
if len(attack_windows) > 0:
    print("DDoS attacks detected in the following windows:")
    for window in attack_windows:
        start_index, end_index, ip_src_values = window
        num = num + len(ip_src_values)
        print(f"Window {start_index}-{end_index}")
        print("IP src values:", ip_src_values)
else:
    print("No DDoS attacks detected.")

print(num2/50)
print(num)
num2 = num2/50
print("Accuracy-:", (((num))/(num2)))