#!/bin/bash

# Assuming you have two text files: file1.txt and file2.txt
file1="processed_data/CESNET_domains_530k.txt"
file2="processed_data/cesnet_intersect_50threshold_150k.txt"

# Sort the files
sorted_file1=$(sort "$file1")
sorted_file2=$(sort "$file2")

# Use comm to find common lines
common_lines=$(comm -12 <(echo "$sorted_file1") <(echo "$sorted_file2"))

# Use comm to find lines unique to file1
unique_lines_file1=$(comm -23 <(echo "$sorted_file1") <(echo "$sorted_file2"))

# Count the number of common lines
num_common_lines=$(echo "$common_lines" | wc -l)

# Count the number of lines unique to file1
num_unique_lines_file1=$(echo "$unique_lines_file1" | wc -l)

# Print the results
echo "Number of common lines between $file1 and $file2: $num_common_lines"
echo "Number of lines in $file1 but not in $file2: $num_unique_lines_file1"
