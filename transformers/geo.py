from pandas import DataFrame
import numpy as np
import category_encoders as ce


def add_countries_count(df: DataFrame) -> DataFrame:
    """
    Calculate number of countries for each domain.
    Input: DF with countries column
    Output: DF with countries_count column added
    """
    df['countries_count'] = df['countries'].apply(lambda countries: len(list(set(countries))) if countries is not None else 0)
    return df


def get_stddev(values):
    if values is None:
        return 0.0
    v = [float(x) for x in values if x is not None]
    if 0 <= len(v) <= 1:
        return 0.0
    return float(np.std(v))

def add_coord_stddev(df: DataFrame) -> DataFrame:
    """
    Calculate standard deviation of coordinates.
    Input: DF with longitues and latitudes columns
    Output: DF with lat_stddev and lon_stddev columns added
    """
    df['lat_stddev'] = df['latitudes'].apply(get_stddev)
    df['lon_stddev'] = df['longitudes'].apply(get_stddev)
    return df


def geo(df: DataFrame) -> DataFrame:
    df = add_countries_count(df)
    df = add_coord_stddev(df)


    #encoder= ce.BinaryEncoder(cols=['countries'],return_df=True)

    return df