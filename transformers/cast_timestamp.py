import numpy as np
from pandas import DataFrame, api, Int64Dtype

def cast_timestamp(df: DataFrame):
    """
    Cast timestamp fields to seconds since epoch.
    """
    for col in df.columns:
        if api.types.is_datetime64_ns_dtype(df[col]) or api.types.is_timedelta64_ns_dtype(df[col]):
            df[col] = df[col].dt.floor('s').astype(np.int64)
            # replace minimum int with null
            df[col] = df[col].replace(np.iinfo(np.int64).min, np.nan)

    return df