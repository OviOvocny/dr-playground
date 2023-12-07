import click
import os
import pyarrow.parquet as pq
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import logging
from pyarrow import Table
from colorama import init, Fore, Style
import pickle
import seaborn as sns
import warnings
warnings.filterwarnings("ignore", category=FutureWarning, module="pandas.api.types")
warnings.filterwarnings("ignore", message="is_sparse is deprecated", category=FutureWarning)
warnings.filterwarnings("ignore", message="is_categorical_dtype is deprecated", category=FutureWarning)

class FeatureEngineeringCLI:
    def __init__(self, benign_path: str, malign_path: str):
        self.benign_path = benign_path
        self.malign_path = malign_path
        self.logger = self.configure_logger()
        self.DEFAULT_INPUT_DIR = "../../floor"
        self.nontraining_fields = [
            "dns_evaluated_on",
            "rdap_evaluated_on",
            "tls_evaluated_on",
            "ip_data",
            "countries",
            "latitudes",
            "longitudes",
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
        ]
    def print_header(self, message: str) -> None:
        header = f"{'=' * len(message)}"
        self.logger.info(self.color_log(header, Fore.CYAN))
        self.logger.info(self.color_log(message, Fore.CYAN))
        self.logger.info(self.color_log(header, Fore.CYAN))


    def configure_logger(self) -> logging.Logger:
        logger = logging.getLogger(__name__)
        logger.setLevel(logging.INFO)

        file_handler = logging.FileHandler('feature_engineering.log')
        file_handler.setLevel(logging.INFO)

        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)

        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)

        logger.addHandler(file_handler)
        logger.addHandler(console_handler)

        return logger

    def color_log(self, message: str, color: str = Fore.GREEN) -> str:
        return f"{color}{message}{Style.RESET_ALL}"

    def load_pickled_data(self) -> tuple:
        shap_values = pickle.load(open("../../shap_values.pickle.dat", "rb"))
        model = pickle.load(open("../../xgboost_model.pickle.dat", "rb"))
        X_train = pickle.load(open("../../X_train.pickle.dat", "rb"))
        return shap_values, model, X_train

    def drop_nontrain(self, table: Table) -> Table:
        """
        Drop non-training columns.
        """
        fields = [x for x in self.nontraining_fields if x in table.column_names]
        return table.drop(fields)

    def get_feature_with_highest_shap(self, shap_values: np.ndarray, dataset: pd.DataFrame, sample_index: int) -> tuple:
        abs_shap_values = np.abs(shap_values[sample_index, :])
        highest_shap_index = np.argmax(abs_shap_values)

        # Get the corresponding feature name and value from the dataset
        feature_name = dataset.columns[highest_shap_index]
        feature_value = dataset.iloc[sample_index, highest_shap_index]

        return feature_name, feature_value

    def perform_feature_engineering(self) -> None:
        benign_path = os.path.join(self.DEFAULT_INPUT_DIR, self.benign_path) if self.benign_path else None
        malign_path = os.path.join(self.DEFAULT_INPUT_DIR, self.malign_path) if self.malign_path else None
        #load shap values, model and X_train
        shap_values, model, X_train = self.load_pickled_data()
        
        self.print_header("Performing Feature Engineering")
        self.logger.info(f'Benign dataset path: {benign_path}')
        self.logger.info(f'Malign dataset path: {malign_path}')       
        data = pq.read_table(benign_path)
        data2 = pq.read_table(malign_path)

        # Drop non-training columns
        data = self.drop_nontrain(data)
        data2 = self.drop_nontrain(data2)

        # Convert to pandas DataFrame if needed
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
        for key in ratios:
            self.logger.info(self.color_log(f'Possibly time demanding feature: {key}', Fore.YELLOW))
        # Sort features by ratio in descending order (including the timedelta columns)
        sorted_features = sorted(ratios, key=ratios.get, reverse=True)[:9]  # Select top 9 features
        custom_colors = ['#1f77b4', '#ff7f0e']  # Blue for Benign, Orange for Phishing
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
        plt.close()

        
        self.logger.info(self.color_log('Choosing most relevant features based on feature_importances_', Fore.YELLOW))
        feature_importances = model.feature_importances_
        normalized_importances = (feature_importances - np.min(feature_importances)) / (np.max(feature_importances) - np.min(feature_importances))
        # Get the indices that would sort the importances array
        sorted_indices = np.argsort(feature_importances)[::-1]
        top_20_indices = sorted_indices[:20]

        # Plotting the top 20 feature importances
        plt.figure(figsize=(10, 8))
        sns.barplot(x=normalized_importances[top_20_indices], y=X_train.columns[top_20_indices], orient='h')
        plt.title('Top 20 Feature Importances')
        plt.xlabel('Importance')
        plt.ylabel('Features')
        plt.tight_layout(pad=1.0)  # Increase padding to avoid cropping
        plt.savefig('../../false_positives/images/top_20_feature_importances.png', dpi=300)  # Save the plot as a high-resolution PNG

        self.print_header("Saving Results")
        
        self.logger.info(self.color_log('Saved possible time-dependent features to:'
                         ' ../../false_positives/images/relative_freq_histograms.png', Fore.GREEN))
        self.logger.info(self.color_log('Saved top 20 feature importances plot to:'
                         ' ../../false_positives/images/top_20_feature_importances.png', Fore.GREEN))


@click.command()
@click.option('--benign', '-b', help='Filename of benign dataset')
@click.option('--malign', '-m', help='Filename of malign dataset')
def feature_engineering(benign: str, malign: str) -> None:
    fe_cli = FeatureEngineeringCLI(benign, malign)
    fe_cli.perform_feature_engineering()

if __name__ == '__main__':
    feature_engineering()
