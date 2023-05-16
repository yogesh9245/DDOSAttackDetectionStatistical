import matplotlib.pyplot as plt
import numpy as np

# Define a function to calculate entropy
def entropy(p):
    return -np.sum(p * np.log2(p))

# Define a probability distribution
p = np.linspace(0.01, 1, 100)

# Calculate the corresponding entropy values
H = np.array([entropy([q, 1 - q]) for q in p])

# Plot the graph
plt.plot(p, H)
plt.xlabel('Probability')
plt.ylabel('Entropy')
plt.title('Entropy vs. Probability')
plt.show()
