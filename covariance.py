import pandas as pd
import numpy as np

# Load the dataset
data = pd.read_csv('your_dataset.csv')

# Define the features
features = ['packet_size', 'num_packets', 'duration']

# Calculate the covariance matrix
cov_matrix = np.cov(data[features].T)

# Define a threshold value
threshold = 2.5

# Detect DDOS attacks using Mahalanobis distance
for i, row in data.iterrows():
    x = row[features].values.reshape(1,-1)
    mahalanobis_dist = np.sqrt(np.dot(np.dot((x - np.mean(data[features], axis=0)), np.linalg.inv(cov_matrix)), (x - np.mean(data[features], axis=0)).T))[0,0]
    if mahalanobis_dist > threshold:
        print("DDOS attack detected at index:", i)
