import csv

def delete_rows(csv_file, start_index, end_index):
    with open(csv_file, 'r') as file:
        reader = csv.reader(file)
        rows = list(reader)

    del rows[start_index:end_index + 1]

    with open(csv_file, 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerows(rows)

# Example usage
csv_file = 'FlowStatsfile.csv'
start_index = 20000  # Start index of the range (0-based index)
end_index = 100000  # End index of the range (0-based index)

delete_rows(csv_file, start_index, end_index)