#!/usr/bin/env python
# coding: utf-8

# In[9]:


#to be able to run your async code in the notebook
import nest_asyncio
import sys
nest_asyncio.apply()
import os
import subprocess
from typing import List, Tuple, Optional
import pyarrow.parquet as pq
import pandas as pd
import matplotlib.pyplot as plt
from tqdm.notebook import tqdm  # tqdm.notebook for Jupyter notebook
from dotenv import load_dotenv
from PyPDF2 import PdfMerger
import math
import requests
import datetime
from matplotlib.backends.backend_pdf import PdfPages
from requests.exceptions import RequestException


# In[10]:


mode = 'benign'  # You can change this to 'benign' to read from the benign dataset
input_mode = 'parquet'  # You can change this to 'txt'
# Maximum of api calls for VirusTotal, current academic api is 20k per day
batch_size = 20000


# ## DomainAnalyzer
# **Objective**: Define the `DomainAnalyzer` class that will handle domain analysis tasks.
# 
# - **Functions Included**:
#     - `__init__`: Initializes the `DomainAnalyzer` with a VirusTotal API key loaded from an environment variable.
#     - `__enter__` and `__exit__`: Context management methods to handle the setup and cleanup of the client.
#     - `initialize_client`: Load API key and initialize the vt.Client.
#     - `check_domain`: Fetch information for a specific domain.
#     - `get_verdict`: Determine the verdict of the analysis based on the domain's analysis stats.
#     - `is_domain_live`: Check if a domain is live by calling a bash script.
#     - `extract_domain_data`: Extract necessary data from the domain result.
#     - `load_previous_data`: Load previously processed domain data from a CSV file.
#     - `save_data`: Save the DataFrame containing domain data to a CSV file.
#     - `generate_report`: Generate a report based on the DataFrame and save it as a PDF.
#     - `process_selected_domains`: Process the domains based on the mode ('malign' or 'benign') in batches.

# In[11]:


class DomainAnalyzer:
    def __init__(self):
        self.api_key = self._load_api_key()
        self.headers = self._create_headers()

    @staticmethod
    def _load_api_key():
        load_dotenv()
        api_key = os.getenv('VT_API_KEY')
        if api_key is None:
            raise ValueError("API key is not set. Please set the VT_API_KEY environment variable.")
        return api_key

    def _create_headers(self):
        return {"x-apikey": self.api_key, "Accept": "application/json"}

    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_value, traceback):
        pass
    
    def check_domain(self, domain: str) -> Optional[dict]:
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        response = requests.get(url, headers=self.headers)
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 429:
            print(f"Quota exceeded when attempting to fetch information for domain {domain}.")
            return "Quota Exceeded"
        else:
            print(f"Error: Unable to fetch information for domain {domain}. {response.text}")
            return None

    def _determine_verdict(self, analysis_stats: dict) -> str:
        return "Malign" if analysis_stats.get('malicious', 0) > 0 or analysis_stats.get('suspicious', 0) > 1 else "Benign" 
        
    def _is_domain_live(self, domain: str) -> str:
        try:
            result = subprocess.run(['./livetest.sh', domain], capture_output=True, text=True)
            return "Alive" if result.stdout.strip() == '1' else "Dead"
        except Exception as e:
            print(f"Error: Unable to check if domain {domain} is live. {e}")
            return "Unknown"
        
    def _format_timestamp(self, timestamp):
        return datetime.datetime.utcfromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')

    def extract_domain_data(self, domain: str, result: dict) -> Optional[Tuple]:
        try:
            attributes = result['data']['attributes']
            # print(attributes)
            analysis_stats = attributes['last_analysis_stats']
            verdict = self._determine_verdict(analysis_stats)
            detection_ratio = f"{analysis_stats['malicious']}/{analysis_stats['malicious'] + analysis_stats['harmless']}"

            last_analysis_date = attributes.get('last_analysis_date', attributes.get('last_submission_date', 0))
            formatted_timestamp = self._format_timestamp(last_analysis_date) if last_analysis_date else 'N/A'

            domain_status = self._is_domain_live(domain)
            #print all stats:
            print(f"Domain: {domain}, Verdict: {verdict}, Detection Ratio: {detection_ratio}, Timestamp: {formatted_timestamp}, Harmless: {analysis_stats.get('harmless', 0)}, Malicious: {analysis_stats.get('malicious', 0)}, Suspicious: {analysis_stats.get('suspicious', 0)}, Live Status: {domain_status}")
            return (domain, verdict, detection_ratio, formatted_timestamp, analysis_stats.get('harmless', 0), analysis_stats.get('malicious', 0), analysis_stats.get('suspicious', 0), domain_status)
        except KeyError:
            print(f"Error: Could not extract analysis stats for domain {domain}")
            return None

    def load_previous_data(self, mode: str) -> pd.DataFrame:
        """
        Load previously processed domain data from a CSV file or text file.
        """

        previous_data_filename = f'previous_data_{mode}.csv'
        if os.path.exists(previous_data_filename):
            return pd.read_csv(previous_data_filename)
        else:
            columns = ["Domain", "Verdict", "Detection Ratio", "Detection Timestamp", "Harmless", "Malicious", "Suspicious", "Live Status"]
            return pd.DataFrame(columns=columns)

    def save_data(self, df: pd.DataFrame, mode) -> None:
        """
        Save the DataFrame containing domain data to a CSV file or text file.
        """

        df.to_csv(f'previous_data_{mode}.csv', index=False)

    def save_checkpoint(self, data, processed_domains, mode, total_processed):
        columns = ["Domain", "Verdict", "Detection Ratio", "Detection Timestamp", "Harmless", "Malicious", "Suspicious", "Live Status"]
        new_df = pd.DataFrame(data, columns=columns)

        # Load the previous data
        old_df = self.load_previous_data(mode)
        
        # Merge the old and new data, removing duplicates
        merged_df = pd.concat([old_df, new_df]).drop_duplicates(subset=['Domain']).reset_index(drop=True)
        self.save_data(merged_df, mode)

        # Overwrite the processed domains file with the updated list
        processed_domains_file = f"processed_domains_{mode}.txt"
        with open(processed_domains_file, 'w') as file:
            file.write('\n'.join(processed_domains))
        print(f"Checkpoint saved to previous_data_{mode}.csv and processed_domains_{mode}.txt")

    def generate_report(self, df: pd.DataFrame, output_filename: str, rows_per_page: int = 500) -> None:
        """
        Generate a report based on the DataFrame and save it as a PDF, including a summary at the end.
        """
        num_pages = math.ceil(len(df) / rows_per_page)

        benign_count = len(df[df['Verdict'] == 'Benign'])
        malign_count = len(df[df['Verdict'] == 'Malign'])
        total_count = len(df)

        with PdfPages(output_filename) as pdf_pages:
            for page in range(num_pages):
                start_row = page * rows_per_page
                end_row = start_row + rows_per_page
                page_df = df[start_row:end_row]

                # If it's the last page, add the summary rows
                if page == num_pages - 1:
                    page_df = page_df.fillna('-')
                    summary_df = pd.DataFrame({
                        "Domain": ["", ""],
                        "Verdict": ["Benign count", "Malign count"],
                        "Detection Ratio": [f"{benign_count}/{total_count}", f"{malign_count}/{total_count}"],
                        # Other columns can be filled with appropriate data or left empty
                    }).reindex(columns=page_df.columns).fillna('-')

                    page_df = pd.concat([page_df, summary_df], ignore_index=True)

                fig_height = max(len(page_df) * 0.01, 4.8)  # Ensure a minimum height
                fig, ax = plt.subplots(figsize=(11, fig_height))
                
                ax.axis('off')  # Hide axes
                plt.tight_layout(pad=0.2)

                colWidths = [
                    max(page_df["Domain"].apply(lambda x: len(x) if x is not None else 0).max() * 0.25, 0.1) * 0.02 if column == "Domain" 
                    else 0.15 if column == "Detection Timestamp" 
                    else 0.1 for column in page_df.columns
                ]

                tab = pd.plotting.table(ax, page_df, loc='upper center', colWidths=colWidths, cellLoc='center', rowLoc='center')
                tab.auto_set_font_size(False)
                tab.set_fontsize(8)
                tab.scale(1.2, 1.2)

                for key, cell in tab.get_celld().items():
                    if key[0] == 0 or key[1] == -1:
                        cell.get_text().set_weight('bold')
                    if 'Verdict' in page_df.columns:
                        if cell.get_text().get_text() == 'Malign':
                            cell.set_text_props(color='red')
                        elif cell.get_text().get_text() == 'Benign':
                            cell.set_text_props(color='green')
                    if 'Live Status' in page_df.columns:
                        if cell.get_text().get_text() == 'Live':
                            cell.set_text_props(color='green')
                        elif cell.get_text().get_text() == 'Dead':
                            cell.set_text_props(color='red')
                    if key[1] == -1:
                        cell.set_visible(False)
                    if page == num_pages - 1 and key[0] >= len(page_df) - 1:  # This line is changed
                        cell.set_text_props(weight='bold')
                        cell.get_text().set_color('black')
                        cell.set_facecolor('lightgrey')

                pdf_pages.savefig(fig, bbox_inches='tight')
                plt.close(fig)

    def process_selected_domains(self, input_mode: str, mode: str, batch_size) -> pd.DataFrame:
        """
        Process the domains based on the mode ('malign' or 'benign') in batches.
        """
        if input_mode not in ['parquet', 'txt']:
            print(f"Invalid input mode '{input_mode}'. Please use 'parquet' or 'txt'.")
            return pd.DataFrame()

        paths = {
            'parquet': {
                'malign': '../floor/phishing_since_2402.parquet',
                'benign': '../floor/benign_2310.parquet'
            },
            'txt': {
                'malign': '../floor/malware_Norbi.txt',
                'benign': '../floor/CESNET_domains_530K.txt',
            }
        }
        # Read the selected Parquet file or text file and get the domain names
        if input_mode == 'parquet':
            table = pq.read_table(paths[input_mode][mode])
            domain_names = table.column('domain_name').to_pandas()
        else:  # input_mode == 'txt'
            #open the file and read the lines
            with open(paths[input_mode][mode], 'r') as file:
                domain_names = file.read().splitlines()

        # Load the processed domains
        processed_domains_file = f"processed_domains_{mode}.txt"

        
        if os.path.exists(processed_domains_file):
            with open(processed_domains_file, 'r') as file:
                processed_domains = file.read().splitlines()
        else:
            processed_domains = []

        data = []
        processed_in_this_run = 0
        total_processed = len(processed_domains)
        
        progress_bar = tqdm(total=len(domain_names), desc='Processing domains', unit='domain')
        for domain in domain_names:
            progress_bar.update(1)
            if domain not in processed_domains:
                try:
                    result = self.check_domain(domain)
                    if result == "Quota Exceeded":
                        # Quota exceeded, generate report and exit
                        print("Quota is exceeded, generating report...")
                        df = self.load_previous_data(mode)
                        df.sort_values(by=['Verdict', 'Live Status'], ascending=[False, False], inplace=True)
                        df.dropna(inplace=True)
                        progress_bar.close()
                        return df
                    elif result:
                        # Extract data if domain check was successful
                        data.append(self.extract_domain_data(domain, result))
                        processed_domains.append(domain)  # Assuming processed_domains is a set
                        processed_in_this_run += 1
                        total_processed += 1
                        
                        # Checkpoint save logic remains unchanged
                        if total_processed % 1000 == 0:
                            self.save_checkpoint(data, processed_domains, mode, total_processed)
                except Exception as e:
                    print(f"Unexpected error occurred: {e}")
                if processed_in_this_run >= batch_size:
                    break
        progress_bar.close()

        self.save_checkpoint(data, processed_domains, mode, total_processed)
        columns = ["Domain", "Verdict", "Detection Ratio", "Detection Timestamp", "Harmless", "Malicious", "Suspicious", "Live Status"]
        
        # Create a DataFrame from the newly processed data
        new_df = pd.DataFrame(data, columns=columns)
        old_df = self.load_previous_data(mode)

        if old_df.empty:
            merged_df = new_df
        elif new_df.empty:
            merged_df = old_df
        else:
            merged_df = pd.concat([old_df, new_df]).drop_duplicates(subset=['Domain']).reset_index(drop=True)
        
        merged_df.sort_values(by=['Verdict', 'Live Status'], ascending=[False, False], inplace=True)
        merged_df.dropna(inplace=True)
        # Save the merged data
        self.save_data(merged_df, mode)
        #print how many domains were processed in total, also include percentages
        print(f"Total number of domains processed: {len(merged_df)} out of {len(domain_names)} ({len(merged_df)/len(domain_names)*100:.2f}%)")
        return merged_df


# **Objective**: Utilize the `DomainAnalyzer` class to process and analyze domains.
# 
# - **Steps**:
#     1. Instantiate the `DomainAnalyzer` class.
#     2. Use the `process_selected_domains` method to process domains based on the specified mode and batch size.
#     3. If domains are processed successfully, generate and save a report using the `generate_report` method.
# 
# **Note**: Ensure that you have the necessary files, API keys, and configurations before running this cell.
# 

# In[12]:


# Example usage in a Jupyter notebook cell:
with DomainAnalyzer() as analyzer:  # Using the analyzer as a context manager
    df = analyzer.process_selected_domains(input_mode, mode, batch_size)  # This should generate your DataFrame df
    if df is not None and not df.empty:  # Ensure that df is not empty or None
        analyzer.generate_report(df, f'{mode}_VT_check.pdf')  # This will use the DataFrame df
        print(f'Report saved as {mode}_VT_check.pdf')
    else:
        print(f"No domains processed for mode '{mode}'. No report generated.")

