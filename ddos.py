import numpy as np
from math import log2
import pandas as pd
data = pd.read_csv("dataset_sdn.csv")
print(data.head(20))
pktin = data.loc[:,'packetins']
print(pktin.head(5))

for i in pktin:
    print(i)
# front = -1
# def receive_packet():
#     front += 1
#     print(pktin[front])
    

# # Define function to calculate Shannon entropy of a string
# def shannon_entropy(string):
#     prob = [float(string.count(c)) / len(string) for c in dict.fromkeys(list(string))]
#     entropy = -sum([p * log2(p) for p in prob])
#     return entropy

# # Set parameters
# window_size = 1000  # Number of packets in the sliding window
# threshold = 4.0  # Threshold for DDoS detection

# # Initialize sliding window
# window_packets = []

# # Read incoming packets and detect DDoS attacks
# while True:
#     packet = receive_packet()  # Function to receive incoming packets
#     break
    
#     # Add packet to sliding window
#     window_packets.append(packet)
    
#     # Remove oldest packet from sliding window if window size is exceeded
#     if len(window_packets) > window_size:
#         window_packets.pop(0)
    
#     # Calculate Shannon entropy of the sliding window
#     window_entropy = shannon_entropy(''.join(window_packets))
    
#     # Detect DDoS attack if entropy exceeds threshold
#     if window_entropy > threshold:
#         print('DDoS attack detected! Entropy:', window_entropy)
