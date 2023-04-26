from pandas import DataFrame
from ._helpers import clean_list

def mean_of_existing_values(values):
    """
    Calculate mean of list of values, ignoring None values.
    Input: list of floats or None values
    Output: mean of values or -1
    """
    clean = clean_list(values)
    return sum(clean) / len(clean) if len(clean) > 0 else -1

def max_of_existing_values(values):
    """
    Calculate max of list of values, ignoring None values.
    Input: list of floats or None values
    Output: max of values or -1
    """
    clean = clean_list(values)
    return max(clean) if len(clean) > 0 else -1

def rtt_mean(df: DataFrame) -> DataFrame:
    """
    Calculate mean RTT for all IPs in each domain.
    Input: DF with average_rtt column (list of floats)
    Output: DF where average_rtt is replaced by mean value
    """
    df['average_rtt'] = df['average_rtt'].apply(mean_of_existing_values)
    return df