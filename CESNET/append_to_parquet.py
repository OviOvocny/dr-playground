import sys
import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq
import re
import tldextract

# Adjust the regular expressions for more lenient domain validation
domain_pattern = re.compile(r'^(?!-)[A-Za-z0-9-]{1,63}(\.[A-Za-z0-9-]{1,63})*(\.[A-Za-z]{2,})$')
ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
exclude_pattern = re.compile(r'[*$:;*_]')  

tldextractor = tldextract.TLDExtract(suffix_list_urls=None)

def is_valid_domain(domain):
    return bool(domain_pattern.match(domain)) and \
           not bool(ip_pattern.match(domain)) and \
           not bool(exclude_pattern.search(domain))

def clean_domain(domain):
    return domain[4:] if domain.startswith('www.') else domain

def append_to_parquet(csv_file_path, parquet_file_path, cutoff=600):  # Increased cutoff
    df_csv = pd.read_csv(csv_file_path)
    df_csv.drop(columns=['CNT'], inplace=True)
    
    df_csv['DOMAIN'] = df_csv['DOMAIN'].apply(lambda x: clean_domain(x) if pd.notnull(x) else x)
    df_csv.dropna(subset=['DOMAIN'], inplace=True)
    df_csv = df_csv[df_csv['DOMAIN'].map(is_valid_domain)]

    df_csv['suffix'] = df_csv['DOMAIN'].map(lambda d: tldextractor(d).suffix)

    table = pa.Table.from_pandas(df_csv, preserve_index=False)

    try:
        parquet_table = pq.read_table(parquet_file_path)
        combined_table = pa.concat_tables([parquet_table, table])
    except FileNotFoundError:
        combined_table = table

    df_combined = combined_table.to_pandas()
    df_combined.drop_duplicates(subset=['DOMAIN'], inplace=True)
    df_combined = df_combined.groupby('suffix').head(cutoff)

    reduced_table = pa.Table.from_pandas(df_combined, preserve_index=False)
    pq.write_table(reduced_table, parquet_file_path)

def main():
    if len(sys.argv) != 3:
        print("Usage: python append_to_parquet.py <csv_file_path> <parquet_file_path>")
        sys.exit(1)

    csv_file_path = sys.argv[1]
    parquet_file_path = sys.argv[2]

    append_to_parquet(csv_file_path, parquet_file_path)

if __name__ == "__main__":
    main()
