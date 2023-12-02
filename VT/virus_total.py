import os
import subprocess
import requests
import pandas as pd
import matplotlib.pyplot as plt
from tqdm import tqdm
from dotenv import load_dotenv
from datetime import datetime
from typing import List, Tuple, Optional


class DomainAnalyzer:
    def __init__(self):
        self.api_key = self._load_api_key()
        self.headers = self._create_headers()

    @staticmethod
    def _load_api_key():
        load_dotenv()
        api_key = os.getenv('VT_API_KEY')
        if not api_key:
            raise ValueError("API key is not set. Please set the VT_API_KEY environment variable.")
        return api_key

    def _create_headers(self):
        return {"x-apikey": self.api_key, "Accept": "application/json"}

    @staticmethod
    def _read_domains(filename: str) -> List[str]:
        with open(filename, "r") as file:
            return [line.strip() for line in file if line.strip()]

    def _check_domain(self, domain: str) -> Optional[dict]:
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        response = requests.get(url, headers=self.headers)
        return response.json() if response.ok else None

    def _get_verdict(self, stats: dict) -> str:
        return "Malign" if stats.get('malicious', 0) > 0 or stats.get('suspicious', 0) > 1 else "Benign"

    def _is_domain_live(self, domain: str) -> str:
        try:
            result = subprocess.run(['./livetest.sh', domain], capture_output=True, text=True)
            return "Alive" if result.stdout.strip() == '1' else "Dead"
        except Exception as e:
            print(f"Error: {e}")
            return "Unknown"

    def _extract_data(self, domain: str, result: dict) -> Optional[Tuple]:
        try:
            attributes = result['data']['attributes']
            stats = attributes['last_analysis_stats']
            verdict = self._get_verdict(stats)
            ratio = f"{stats['malicious']}/{stats['malicious'] + stats['harmless']}"
            timestamp = self._format_timestamp(attributes.get('last_analysis_date', 0))
            status = self._is_domain_live(domain)
            return domain, verdict, ratio, timestamp, stats.get('harmless', 0), stats.get('malicious', 0), stats.get('suspicious', 0), status
        except KeyError:
            return None

    @staticmethod
    def _format_timestamp(timestamp: int) -> str:
        return datetime.utcfromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S') if timestamp else 'N/A'

    def process_domains(self, filename: str) -> pd.DataFrame:
        domains = self._read_domains(filename)
        data = [(self._extract_data(domain, self._check_domain(domain))) for domain in tqdm(domains, desc="Processing domains")]
        data = [d for d in data if d is not None]
        df = pd.DataFrame(data, columns=["Domain", "Verdict", "Detection Ratio", "Detection Timestamp", "Harmless", "Malicious", "Suspicious", "Live Status"])
        df.sort_values(by=['Verdict', 'Live Status'], ascending=[False, False], inplace=True)
        return df.dropna()

    def generate_report(self, df: pd.DataFrame, output_filename: str) -> None:
        benign_count = len(df[df['Verdict'] == 'Benign'])
        malign_count = len(df[df['Verdict'] == 'Malign'])
        total_count = len(df)
        
        benign_row = pd.DataFrame([['', 'Benign count', f'{benign_count}/{total_count}', '', '', '', '', '']], columns=df.columns)
        malign_row = pd.DataFrame([['', 'Malign count', f'{malign_count}/{total_count}', '', '', '', '', '']], columns=df.columns)
        
        df = pd.concat([df, benign_row, malign_row], ignore_index=True)
        # Adjust the height of the figure based on the number of rows in the DataFrame
        fig_height = len(df) * 0.05
        fig, ax = plt.subplots(figsize=(11, fig_height))
        ax.axis('off')  # Hide axes
        plt.tight_layout(pad=0.1)
        
        colWidths = [
            max(df["Domain"].apply(lambda x: len(x) if x is not None else 0.2) * 0.22) * 0.02 if column == "Domain" 
            else 0.15 if column == "Detection Timestamp" 
            else 0.10 for column in df.columns
        ]
        
        tab = pd.plotting.table(ax, df, loc='upper center', colWidths=colWidths, cellLoc='center', rowLoc='center')
        tab.auto_set_font_size(True) 
        tab.set_fontsize(8)  
        tab.scale(1.2, 1.2)

        # Style adjustments (bold headers, colors based on verdict, hiding index)
        for key, cell in tab.get_celld().items():
            if key[0] == 0 or key[1] == -1:
                cell._text.set_weight('bold')
            if cell.get_text().get_text() == 'Malign':
                cell._text.set_color('red')
            elif cell.get_text().get_text() == 'Benign':
                cell._text.set_color('green')
            if key[1] == -1:
                cell.set_visible(False)
            if key[0] in [total_count+1, total_count+2]:  # Special styling for the benign and malign count rows
                cell._text.set_weight('bold')
                cell.set_facecolor('lightgrey')
            if cell.get_text().get_text() == 'Dead':
                cell._text.set_color('red')
            elif cell.get_text().get_text() == 'Alive':
                cell._text.set_color('green')
        
        # Save the table as a PDF
        plt.savefig(output_filename, bbox_inches='tight', dpi=300)
        plt.close()


if __name__ == "__main__":
    analyzer = DomainAnalyzer()
    #fp domains
    # df = analyzer.process_domains("false_positives/highest_shap.txt")
    # analyzer.generate_report(df, 'false_positives/VT/FP_check.pdf')

    df = analyzer.process_domains("cesnet.txt")
    analyzer.generate_report(df, 'cesnet_udajne_benigni.pdf')
