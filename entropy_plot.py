import pandas as pd
import matplotlib.pyplot as plt
import numpy as np

# Load the dataset
data = pd.read_csv('dataset_sdn.csv')

# Define the features
features = ['pktcount', 'bytecount', 'flows', 'packetins', 'pktperflow', 'byteperflow', 'pktrate']

# Define a threshold value
threshold = 1.5

# Define a function to calculate entropy
def entropy(p):
    return -np.sum(p * np.log2(p))

# Define a function to calculate the entropy of each row
def row_entropy(row):
    p = np.array(row[features]) / np.sum(row[features])
    return entropy(p)

# Calculate the entropy of each row
entropy_values = data.apply(row_entropy, axis=1)

# Plot the graph of entropy vs. probability
plt.hist(entropy_values, bins=20, density=True)
plt.xlabel('Entropy')
plt.ylabel('Probability')
plt.title('Entropy vs. Probability')
plt.show()

# Detect DDOS attacks using entropy
for src_ip in data['src'].unique():
    ip_data = data[data['src'] == src_ip]
    for i, row in ip_data.iterrows():
        if row_entropy(row) > threshold:
            print("DDOS attack detected at index:", i, "from source IP address:", src_ip)
