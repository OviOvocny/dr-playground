#!/usr/bin/env python3

import pandas as pd
import sys

def intersect_parquet_files(file1, file2, output_file):
    # Read the parquet files into dataframes
    df1 = pd.read_parquet(file1)
    df2 = pd.read_parquet(file2)
    
    # Make sure columns align
    df2 = df2[df1.columns]
    
    # Find intersection based on 'domain_name'
    common_df = df1[df1['domain_name'].isin(df2['domain_name'])]
    
    # Save to output parquet file
    common_df.to_parquet(output_file)

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: script_name.py <input_file1> <input_file2> <output_file>")
        sys.exit(1)

    intersect_parquet_files(sys.argv[1], sys.argv[2], sys.argv[3])

