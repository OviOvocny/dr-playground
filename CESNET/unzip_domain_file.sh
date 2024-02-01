#!/bin/bash

# Assuming this Bash script is located in the 'CESNET' folder
# and the Python script 'append_to_excel.py' is also in the 'CESNET' folder.

# The name of the Excel file to append domains to
parquet_file="CESNET_domains.parquet"

# Navigate to the data folder where the .gz files are located
cd data

# Process each .gz file
for file in *.gz; do
    # Unzip the file
    gzip -dk "$file"
    csv_file="${file%.gz}"

    # Call the Python script to append the domains to the Excel file
    # Using '../' to go up one level from the 'data' folder to the 'CESNET' folder where the Python script is located
    /usr/bin/python3 ../append_to_parquet.py "$csv_file" "../$parquet_file"

    # Remove the unzipped CSV file
    rm "$csv_file"
done

# Navigate back to the original 'CESNET' folder
cd ..
