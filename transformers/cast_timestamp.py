import numpy as np
from pandas import DataFrame, api

def cast_timestamp(df: DataFrame):
    """
    Cast timestamp fields to seconds since epoch.
    """
    for col in df.columns:
        if api.types.is_datetime64_ns_dtype(df[col]):
            df[col] = df[col].astype('int64') // 10**9
    return df