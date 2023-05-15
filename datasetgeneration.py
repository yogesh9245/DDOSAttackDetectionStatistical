import random
import pandas as pd
# Generate random packet data
packet_data = []
for i in range(1000):
    packet_length = random.randint(50, 500)
    packet = ''.join([random.choice(['0', '1']) for _ in range(packet_length)])
    packet_data.append(packet)

# Create Pandas DataFrame
data = pd.DataFrame({'packet_data': packet_data})
data.to_csv('dataset.csv', index=False)
