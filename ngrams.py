import json
import pandas as pd
from nltk import ngrams, FreqDist

import tldextract

def remove_tld(domain: str) -> str:
    """Function removes tld from
    the domain name

    Args:
        domain (str): Domain name

    Returns:
        str: Domain without TLD
    """
    ext = tldextract.extract(domain)
    subdomain = ext.subdomain
    sld = ext.domain
    result = subdomain + "." + sld if subdomain else sld
    return result

class NgramsAnalyzer:
    """
    A class to analyze domain names and generate frequency distributions of bigrams, trigrams, and tetragrams.
    """

    def __init__(self, file_path):
        """
        Initialize the NgramsAnalyzer object.
        Args:
            file_path (str): The path to the Parquet file.
        """
        self.file_path = file_path
        self.df = None
        self.domain_names = []
        self.all_bigrams = []
        self.all_trigrams = []
        self.all_tetragrams = []  # Added for tetragrams

    def load_data(self):
        """
        Load the Parquet file into a DataFrame.
        """
        self.df = pd.read_parquet(self.file_path)

    def extract_domain_name(self):
        """
        Extract the domain names from the DataFrame.
        """
        self.domain_names = self.df['domain_name'].tolist()

    def generate_ngrams(self):
        """
        Generate all bigrams, trigrams, and tetragrams from the domain name.
        """
        for domain in self.domain_names:
            dom = remove_tld(domain)
            domain_bigrams = list(ngrams(dom, 2))
            domain_trigrams = list(ngrams(dom, 3))
            domain_tetragrams = list(ngrams(dom, 4))  # Added for tetragrams
            self.all_bigrams.extend(domain_bigrams)
            self.all_trigrams.extend(domain_trigrams)
            self.all_tetragrams.extend(domain_tetragrams)  # Added for tetragrams

    def get_most_common_bigrams(self, n):
        """
        Get the n most common bigrams.

        Args:
            n (int): The number of most frequent bigrams we want to retrieve.

        Returns:
            list: Most common bigrams and their frequencies.
        """
        bigram_freq_dist = FreqDist(self.all_bigrams)
        return bigram_freq_dist.most_common(n)

    def get_most_common_trigrams(self, n):
        """
        Get the n most common trigrams.

        Args:
            n (int): The number of most frequent trigrams we want to retrieve.

        Returns:
            list: Most common trigrams and their frequencies.
        """
        trigram_freq_dist = FreqDist(self.all_trigrams)
        return trigram_freq_dist.most_common(n)

    def get_most_common_tetragrams(self, n):
        """
        Get the n most common tetragrams.
        Args:
            n (int): The number of most frequent tetragrams we want to retrieve.
        Returns:
            list: Most common tetragrams and their frequencies.
        """
        tetragram_freq_dist = FreqDist(self.all_tetragrams)
        return tetragram_freq_dist.most_common(n)

    def save_to_json(self, bigram_data, trigram_data, tetragram_data, filename):
        """
        Save the bigram, trigram, and tetragram data to a JSON file.
        Args:
            bigram_data (dict): Dictionary of bigrams and their frequencies.
            trigram_data (dict): Dictionary of trigrams and their frequencies.
            tetragram_data (dict): Dictionary of tetragrams and their frequencies.  # Added for tetragrams
            filename (str): Name of the JSON file to save.
        """
        data = {
            'bigram_freq': bigram_data,
            'trigram_freq': trigram_data,
            'tetragram_freq': tetragram_data  # Added for tetragrams
        }
        with open(filename, 'w') as file:
            json.dump(data, file)

    def analyze_ngrams(self, n, outfile):
        """
        Analyze the ngrams and save the results to a JSON file.
        Args:
            n (int): The number of most frequent ngrams to retrieve.
        """
        self.load_data()
        self.extract_domain_name()
        self.generate_ngrams()

        # Get the n most common bigrams, trigrams, and tetragrams
        most_common_bigrams = self.get_most_common_bigrams(n)
        most_common_trigrams = self.get_most_common_trigrams(n)
        most_common_tetragrams = self.get_most_common_tetragrams(n)  # Added for tetragrams

        # Convert to dictionaries for better manipulation
        bigram_dict = {(''.join(bigram)): count for bigram, count in most_common_bigrams}
        trigram_dict = {(''.join(trigram)): count for trigram, count in most_common_trigrams}
        tetragram_dict = {(''.join(tetragram)): count for tetragram, count in most_common_tetragrams}  # Added for tetragrams

        # Save frequency distributions to a single JSON file
        self.save_to_json(bigram_dict, trigram_dict, tetragram_dict, outfile)  # Modified to include tetragrams


if __name__ == '__main__':
    analyzer = NgramsAnalyzer('floor/phishing.parquet')
    analyzer.analyze_ngrams(50, 'ngram_freq_phishing.json')
    analyzer = NgramsAnalyzer('floor/malware.parquet')
    analyzer.analyze_ngrams(50, 'ngram_freq_malware.json')
    analyzer = NgramsAnalyzer('floor/dga.parquet')
    analyzer.analyze_ngrams(500, 'ngram_freq_dga.json')
