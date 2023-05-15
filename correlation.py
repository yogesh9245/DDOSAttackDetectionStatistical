import pandas as pd

# Load the dataset
data = pd.read_csv('dataset_sdn.csv')

# Define the features
features = ['pktcount', 'bytecount', 'flows', 'packetins', 'pktperflow', 'byteperflow', 'pktrate']

# Calculate the correlation matrix
corr_matrix = data[features].corr()

# Define a threshold value
threshold = 0.9

# Detect DDOS attacks using correlation and detect IP addresses
for src_ip in data['src'].unique():
    ip_data = data[data['src'] == src_ip]
    for i, row in ip_data.iterrows():
        x = row[features]
        if (corr_matrix.abs() > threshold).sum().sum() > len(features):
            print("DDOS attack detected at index:", i, "from source IP address:", src_ip)
