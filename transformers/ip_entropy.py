from pandas import DataFrame

import pandas as pd
import numpy as np

def entropy(values) -> float:
    if values is None:
        return 0.0
    # leave only last 2 octets of each IP
    values = [ip.split('.')[-2:] for ip in values]
    # get unique values and their counts
    _, counts = np.unique(values, return_counts=True)
    # calculate probabilities
    probs = counts / counts.sum()
    # calculate entropy
    return -np.sum(probs * np.log2(probs))

def ip_entropy(df: DataFrame) -> DataFrame:
    """
    Calculate IP entropy for each domain.
    Input: DF with dns_A list of IPs
    Output: DF with ip_entropy column added
    """
    # calculate entropy for each domain
    df['ip_entropy'] = df['dns_A'].apply(entropy)
    return df