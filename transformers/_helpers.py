import math
import numpy as np
from typing import Optional
from pandas import Series


# Here lies a bunch of helper functions that are used in the transformers.
# They are not meant to be used directly, but are imported by the transformers.
# If you feel like you've created a helper function for your transformer 
# that you think could be useful for others, please extract it to here.

def get_stddev(values):
    if values is None:
        return 0.0
    v = [float(x) for x in values if x is not None]
    if 0 <= len(v) <= 1:
        return 0.0
    return float(np.std(v))

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


def clean_list(input: list):
    """
    Takes a list and removes all None values. None input returns empty list.
    """
    if input is None:
        return []
    return [value for value in input if value is not None]


def dict_path(input: dict, path: str):
    """
    Takes a dict and a path string. The path string is a dot-separated list of keys or list indices.
    Returns the value at the end of the path.
    """
    if input is None:
        return None
    for key in path.split('.'):
        if key.isdigit() and isinstance(input, list):
            input = input[int(key)]
        elif input is not None and key in input:
            input = input[key]
        else:
            return None
    return input


def map_dict_to_series(input: dict, mapping: dict, prefix: str = '', dtype=None) -> Series:
    """
    Takes an input dict and a mapping dict. The mapping maps columns names to paths in the input dict {"column": "path.to.0.key"}.
    The new column names are prefixed with the prefix argument. The values are stored in pandas Series.
    """
    if dtype:
        return Series({prefix + new_name: dict_path(input, path) for new_name, path in mapping.items()}, dtype=dtype)
    return Series({prefix + new_name: dict_path(input, path) for new_name, path in mapping.items()})


def get_normalized_entropy(text: str) -> Optional[float]:
    """Function returns the normalized entropy of the
    string. The function first computes the frequency
    of each character in the string using
    the collections.Counter function.
    It then uses the formula for entropy to compute
    the entropy of the string, and normalizes it by
    dividing it by the maximum possible entropy
    (which is the logarithm of the minimum of the length
    of the string and the number of distinct characters
    in the string).

    Args:
        text (str): the string

    Returns:
        float: normalized entropy
    """
    text_len = len(text)
    if text_len == 0:
        return None

    freqs = {}
    for char in text:
        if char in freqs:
            freqs[char] += 1
        else:
            freqs[char] = 1

    entropy = 0.0
    for f in freqs.values():
        p = float(f) / text_len
        entropy -= p * math.log(p, 2)
    return entropy / text_len
