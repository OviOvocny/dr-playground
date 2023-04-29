from pandas import DataFrame

from ._helpers import mean_of_existing_values
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

def add_ip_entropy(df: DataFrame) -> DataFrame:
    """
    Calculate IP entropy for each domain.
    Input: DF with dns_A list of IPs
    Output: DF with ip_entropy column added
    """
    # calculate entropy for each domain
    df['ip_entropy'] = df['dns_A'].apply(entropy)
    return df

def add_rtt_mean(df: DataFrame) -> DataFrame:
    """
    Calculate mean RTT for all IPs in each domain.
    Input: DF with average_rtt column (list of floats)
    Output: DF where average_rtt is replaced by mean value
    """
    df['ip_mean_average_rtt'] = df['average_rtt'].apply(mean_of_existing_values)
    return df

def ip(df: DataFrame) -> DataFrame:
    df = add_ip_entropy(df)
    df = add_rtt_mean(df)
    return df