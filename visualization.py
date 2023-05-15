import pandas as pd
import matplotlib.pyplot as plt

# Assuming the data is stored in a CSV file named 'FlowStatsfile.csv'
data = pd.read_csv('D:\\AI Lab\\Untitled Folder\\ddos\\DDOSAttackDetectionStatistical\\FlowStatsfile.csv')

# Convert timestamp to datetime
data['timestamp'] = pd.to_datetime(data['timestamp'], unit='s')

# Plotting packet count per second over time
plt.figure(figsize=(12, 6))
plt.plot(data['timestamp'], data['packet_count_per_second'])
plt.xlabel('Time')
plt.ylabel('Packet Count per Second')
plt.title('DDoS Attack Detection - Packet Count per Second')
plt.grid(True)
plt.show()

# Plotting byte count per second over time
plt.figure(figsize=(12, 6))
plt.plot(data['timestamp'], data['byte_count_per_second'])
plt.xlabel('Time')
plt.ylabel('Byte Count per Second')
plt.title('DDoS Attack Detection - Byte Count per Second')
plt.grid(True)
plt.show()

# Bar Chart of Protocol Distribution
protocol_counts = data['ip_proto'].value_counts()
plt.figure(figsize=(10, 6))
plt.bar(protocol_counts.index, protocol_counts.values)
plt.xlabel('Protocol')
plt.ylabel('Count')
plt.title('DDoS Attack Detection - Protocol Distribution')
plt.grid(True)
plt.show()

# Scatter Plot of Packet Count vs. Byte Count
plt.figure(figsize=(10, 6))
plt.scatter(data['packet_count'], data['byte_count'])
plt.xlabel('Packet Count')
plt.ylabel('Byte Count')
plt.title('DDoS Attack Detection - Packet Count vs. Byte Count')
plt.grid(True)
plt.show()

# # Line Plot of the Time Series
# plt.figure(figsize=(12, 6))
# plt.plot(data['timestamp'], data['value'])
# plt.xlabel('Time')
# plt.ylabel('Value')
# plt.title('Time Series Data')
# plt.grid(True)
# plt.show()

# Rolling Mean and Standard Deviation
rolling_mean = data['packet_count'].rolling(window=30).mean()
rolling_std = data['packet_count'].rolling(window=30).std()

plt.figure(figsize=(12, 6))
plt.plot(data['packet_count'], label='Original')
plt.plot(rolling_mean, label='Rolling Mean')
plt.plot(rolling_std, label='Rolling Std')
plt.xlabel('Time')
plt.ylabel('Packet Count')
plt.title('Rolling Mean and Standard Deviation')
plt.legend()
plt.grid(True)
plt.show()

# ACF and PACF Plots
from statsmodels.graphics.tsaplots import plot_acf, plot_pacf

plt.figure(figsize=(12, 6))
plot_acf(data['packet_count'], lags=30)
plt.xlabel('Lag')
plt.ylabel('ACF')
plt.title('Autocorrelation Function (ACF)')
plt.grid(True)
plt.show()

plt.figure(figsize=(12, 6))
plot_pacf(data['packet_count'], lags=30)
plt.xlabel('Lag')
plt.ylabel('PACF')
plt.title('Partial Autocorrelation Function (PACF)')
plt.grid(True)
plt.show()


# Compare 'packet_count' and 'byte_count' using line plots
plt.plot(data['timestamp'], data['packet_count'], label='Packet Count')
plt.plot(data['timestamp'], data['byte_count'], label='Byte Count')
plt.xlabel('Timestamp')
plt.ylabel('Count')
plt.title('Comparison of Packet Count and Byte Count')
plt.legend()
plt.show()

# Compare 'packet_count_per_second' and 'byte_count_per_second' using line plots
plt.plot(data['timestamp'], data['packet_count_per_second'], label='Packet Count per Second')
plt.plot(data['timestamp'], data['byte_count_per_second'], label='Byte Count per Second')
plt.xlabel('Timestamp')
plt.ylabel('Count per Second')
plt.title('Comparison of Packet Count per Second and Byte Count per Second')
plt.legend()
plt.show()

# Compare 'label' using a bar plot
label_counts = data['label'].value_counts()
label_counts.plot(kind='bar')
plt.xlabel('Label')
plt.ylabel('Count')
plt.title('Comparison of Labels')
plt.show()
