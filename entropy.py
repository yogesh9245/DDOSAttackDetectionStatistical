import pandas as pd
import numpy as np
import scipy.stats as stats
import matplotlib.pyplot as plt

# Load SDN dataset
sdn_data = pd.read_csv('dataset_sdn.csv')

# Extract relevant columns for analysis
src_ips = sdn_data['src']
dst_ips = sdn_data['dst']
protocols = sdn_data['Protocol']
payloads = []
probabily = []
src_size = src_ips.size
# print(src_size)
for i in range(src_size):
    total_payload = sdn_data['bytecount'][i] - ((sdn_data['packetins'][i])*(sdn_data['flows'][i]))
    # print(total_payload)
    # total_payload = byte_count - (packetins * packet_flow)
    payloads.append(total_payload)

# Define a function to calculate entropy
def entropy(payload):
    payload = str(payload)
    if len(payload) == 0:
        return 0
    entropy = 0
    for x in range(256):
        p_x = float(payload.count(chr(x)))/len(payload)
        # print(p_x) 
        probabily.append(p_x) #
        if p_x > 0:
            entropy += - p_x * np.log2(p_x)
            # print(entropy) 
    return entropy

# Calculate the entropy of the payloads
entropies = [entropy(payload) for payload in payloads]

# Calculate the mean entropy for each source IP
mean_entropies = {}
for i in range(len(src_ips)):
    if src_ips[i] not in mean_entropies:
        mean_entropies[src_ips[i]] = []
    mean_entropies[src_ips[i]].append(entropies[i])

for src_ip in mean_entropies:
    mean_entropies[src_ip] = np.mean(mean_entropies[src_ip])

# Calculate the z-score for each source IP
z_scores = {}
for i in range(len(src_ips)):
    if src_ips[i] not in z_scores:
        z_scores[src_ips[i]] = []
    z_scores[src_ips[i]].append((entropies[i] - mean_entropies[src_ips[i]]) / np.std(mean_entropies[src_ips[i]]))

# Determine if there is an attack
for src_ip in z_scores:
    if np.max(z_scores[src_ip]) > 3:
        print('DDoS attack detected from', src_ip)

plt.hist(entropies)
plt.show()

# plt.plot(probabily,entropies)
# plt.xlabel('Probability')
# plt.ylabel('Entropy')
# plt.title('Entropy vs. Probability')
# plt.show()