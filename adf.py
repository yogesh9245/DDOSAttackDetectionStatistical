import pandas as pd
from statsmodels.tsa.stattools import adfuller

# Define the filename and path of the dataset
filename = 'dataset_sdn.csv'

# Load the dataset into a Pandas DataFrame
data = pd.read_csv(filename)

# Select the relevant attribute for analysis
selected_attribute = 'pktcount'

# Perform the ADF test (Type 0: No constant, no trend)
result = adfuller(data[selected_attribute], autolag='AIC')
test_statistic = result[0]
critical_values = result[4]

# Define the significance level
significance_level = 0.05

# Check if the time series is stationary (potential DDoS attack)
if test_statistic < critical_values['1%']:
    attack_indices = [idx for idx in range(len(data)) if data[selected_attribute][idx] < critical_values['1%']]
    attacking_src_ips = data.loc[attack_indices, 'src']
    print("Potential DDoS attacks detected from the following source IPs:")
    print(attacking_src_ips)
else:
    print("No potential DDoS attacks detected.")
