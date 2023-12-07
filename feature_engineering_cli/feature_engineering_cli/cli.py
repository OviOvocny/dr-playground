import click
import os
import pyarrow.parquet as pq
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import logging
from pyarrow import Table
from colorama import init, Fore, Style


logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Create a file handler and set the logging level
file_handler = logging.FileHandler('feature_engineering.log')
file_handler.setLevel(logging.INFO)

# Create a console handler and set the logging level
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)

# Create a log format
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
file_handler.setFormatter(formatter)
console_handler.setFormatter(formatter)

# Add the file and console handlers to the logger
logger.addHandler(file_handler)
logger.addHandler(console_handler)
def color_log(message, color=Fore.GREEN):
    return f"{color}{message}{Style.RESET_ALL}"


#print szs path
DEFAULT_INPUT_DIR = "../../floor"
nontraining_fields = [
    #"domain_name",
    "dns_evaluated_on",
    "rdap_evaluated_on",
    "tls_evaluated_on",

    # IP data
    "ip_data",
    "countries",
    "latitudes",
    "longitudes",

    # DNS
    "dns_dnssec",
    "dns_zone_dnskey_selfsign_ok",
    "dns_email_extras",
    "dns_ttls",
    "dns_zone",
    "dns_zone_SOA",
    *[f"dns_{t}" for t in ('A', 'AAAA', 'CNAME', 'MX', 'NS', 'SOA', 'TXT')],

    "rdap_registration_date",
    "rdap_last_changed_date",
    "rdap_expiration_date",
    "rdap_dnssec",
    "rdap_entities"

    #"tls_root_cert_validity_remaining",
    #"tls_leaf_cert_validity_remaining"
]

def drop_nontrain(table: Table):
    """
    Drop non-training columns.
    """
    fields = [x for x in nontraining_fields if x in table.column_names]
    return table.drop(fields)

@click.command()
@click.option('--benign', '-b', help='Filename of benign dataset')
@click.option('--malign', '-m', help='Filename of malign dataset')
@click.option('--time-analysis', '-ta', is_flag=True, help='Perform time analysis')
def feature_engineering(benign, malign, time_analysis):
    benign_path = os.path.join(DEFAULT_INPUT_DIR, benign) if benign else None
    malign_path = os.path.join(DEFAULT_INPUT_DIR, malign) if malign else None

    if benign_path and malign_path:
        logger.info(color_log(f'Performing feature engineering on benign dataset: {benign_path} and malign dataset: {malign_path}', Fore.BLUE))
        # Read benign and malign datasets
        data = pq.read_table(benign_path)
        data2 = pq.read_table(malign_path)

    if time_analysis:
        #log that we are determining which features from tls and rdap are time dependant
        logger.info(color_log('Determining which features from tls and rdap are time dependent', Fore.YELLOW))
        data = drop_nontrain(data)
        data2 = drop_nontrain(data2)

        # Convert to pandas DataFrame
        df1 = data.to_pandas()
        df2 = data2.to_pandas()

        # Calculate ratio of benign to phishing for features containing 'tls'
        features_with_validity_len = [col for col in df1.columns if 'validity' in col]
        features_with_lifetime = [col for col in df1.columns if 'lifetime' in col]
        features_with_count = [col for col in df1.columns if 'count' in col]
        features_with_age = [col for col in df1.columns if 'age' in col]
        features_with_active_time = [col for col in df1.columns if 'active_time' in col]
        features_with_period = [col for col in df1.columns if 'period' in col]

        selected_features = features_with_validity_len + features_with_lifetime + features_with_age + features_with_active_time + features_with_period 
        selected_features_without_age = [
            col for col in selected_features if col not in ['rdap_domain_age', 'rdap_domain_active_time', 'rdap_registration_period']
        ]

        ratios = {}
        for feature in selected_features_without_age:
            print(f"Feature: {feature}, Data Type: {df1[feature].dtype}")

            benign_count = df1[feature].count()
            phishing_count = df2[feature].count()
            
            if phishing_count != 0:
                ratio = benign_count / phishing_count
                ratios[feature] = ratio

        # Convert timedelta columns to numeric representation (days) without changing names
        for col in ['rdap_domain_age', 'rdap_domain_active_time', 'rdap_registration_period']:
            df1[col] = df1[col].dt.days
            df2[col] = df2[col].dt.days

        # Calculate counts after converting timedelta columns to days
        for col in ['rdap_domain_age', 'rdap_domain_active_time', 'rdap_registration_period']:
            benign_count = df1[col].count()
            phishing_count = df2[col].count()
            
            if phishing_count != 0:
                ratio = benign_count / phishing_count
                ratios[col] = ratio

        # Sort features by ratio in descending order (including the timedelta columns)
        sorted_features = sorted(ratios, key=ratios.get, reverse=True)[:9]  # Select top 9 features
        custom_colors = ['#1f77b4', '#ff7f0e']  # Blue for Benign, Orange for Phishing

        # Plot histograms for the top 9 features in a 3x3 subplot
        fig, axes = plt.subplots(nrows=3, ncols=3, figsize=(15, 15))

        for i, feature in enumerate(sorted_features):
            ax = axes[i // 3, i % 3]  # Calculate subplot index
            
            lts_benign = df1[feature].fillna(-1.0)
            lts_phishing = df2[feature].fillna(-1.0)
            
            # Plot histograms using the custom color palette
            ax.hist(lts_benign, bins=30, alpha=0.7, label='Benign', density=True, color=custom_colors[0])
            ax.hist(lts_phishing, bins=30, alpha=0.7, label='Phishing', density=True, color=custom_colors[1])
            ax.set_xlabel('Value', fontsize=12)
            ax.set_ylabel('Density', fontsize=12)
            ax.set_title(f'{feature}', fontsize=14)
            ax.legend(prop={'size': 10})

            # Customize tick labels and font sizes
            ax.tick_params(axis='both', which='major', labelsize=10)
            ax.tick_params(axis='both', which='minor', labelsize=8)

            # Adding gridlines and removing spines
            ax.grid(True, linestyle='--', alpha=0.7)
            ax.spines['top'].set_visible(False)
            ax.spines['right'].set_visible(False)

        # Set overall figure title
        fig.suptitle('Relative Frequency Histograms for Top Features', fontsize=16)

        plt.tight_layout(rect=[0, 0.03, 1, 0.95])  # Adjust subplot layout and spacing
        plt.savefig('../../false_positives/images/relative_freq_histograms.png', dpi=300)  # Save the plot as a high-resolution PNG
        
        logger.info(color_log('Saved possible time dependand features of TLS and RDAP to ../../false_positives/images/relative_freq_histograms.png', Fore.GREEN))

if __name__ == '__main__':
    feature_engineering()
