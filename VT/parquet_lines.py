import sys
import pyarrow.parquet as pq

def count_records(parquet_file):
    try:
        table = pq.read_table(parquet_file)
        num_records = len(table)
        print(f"Number of records in '{parquet_file}': {num_records}")
    except Exception as e:
        print(f"Error: {e}")


def print_first_record(parquet_file):
    try:
        table = pq.read_table(parquet_file)
        if len(table) > 0:
            first_record = table[0]  # Get the first record
            print(f"First record in '{parquet_file}':\n{first_record}")
        else:
            print(f"No records found in '{parquet_file}'")
    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python count_records.py <parquet_file>")
    else:
        parquet_file = sys.argv[1]
        count_records(parquet_file)
        print_first_record(parquet_file)