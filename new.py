import pandas as pd
from statsmodels.tsa.stattools import adfuller

# Load the dataset
data = pd.read_csv("TFTP_mini.csv")

# Select relevant columns for analysis
columns = ["Timestamp", "Total Length of Fwd Packets", "Total Length of Bwd Packets"]
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
print(p_value)
if p_value < threshold:
    print("DDoS attack detected.")
else:
    print("No DDoS attack detected.")
