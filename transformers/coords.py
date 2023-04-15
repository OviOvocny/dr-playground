from pandas import DataFrame
import numpy as np

def get_stddev(values):
    if values is None:
        return 0.0
    v = [float(x) for x in values if x is not None]
    if 0 <= len(v) <= 1:
        return 0.0
    return float(np.std(v))

def coord_stddev(df: DataFrame) -> DataFrame:
    """
    Calculate standard deviation of coordinates.
    Input: DF with longitues and latitudes columns
    Output: DF with lat_stddev and lon_stddev columns added
    """
    df['lat_stddev'] = df['latitudes'].apply(get_stddev)
    df['lon_stddev'] = df['longitudes'].apply(get_stddev)
    return df