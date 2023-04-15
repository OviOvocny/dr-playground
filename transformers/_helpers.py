from pandas import Series

# Here lies a bunch of helper functions that are used in the transformers.
# They are not meant to be used directly, but are imported by the transformers.
# If you feel like you've created a helper function for your transformer 
# that you think could be useful for others, please extract it to here.

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

def map_dict_to_series(input: dict, mapping: dict, prefix: str = '', dtype = None) -> Series:
    """
    Takes an input dict and a mapping dict. The mapping maps columns names to paths in the input dict {"column": "path.to.0.key"}.
    The new column names are prefixed with the prefix argument. The values are stored in pandas Series.
    """
    if dtype:
        return Series({ prefix + new_name: dict_path(input, path) for new_name, path in mapping.items() }, dtype=dtype)
    return Series({ prefix + new_name: dict_path(input, path) for new_name, path in mapping.items() })