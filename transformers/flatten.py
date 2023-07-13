from pandas import DataFrame, Series, concat
from ._helpers import map_dict_to_series

def map_ip_data(ip_data):
    if ip_data is None:
        return Series({
            'countries': None,
            'latitudes': None,
            'longitudes': None,
        })
    else:
        ip_data = [ip for ip in ip_data if ip['geo'] is not None]
        return Series({
            'countries': [ip['geo']['country'] for ip in ip_data],
            'latitudes': [ip['geo']['latitude'] for ip in ip_data],
            'longitudes': [ip['geo']['longitude'] for ip in ip_data],
        })

# This is just a function that takes nested fields and surfaces them
# into their own columns. Sounds simple, but it's not. The fields
# are nested in a variety of ways, and some of them are lists of
# dictionaries.
#
# This is probably a pretty slow way to do it, but it works.
# If you are a pandas wizard and know how to do this faster, 
# please make it so. This is the slowest transformation by far.
def flatten(df: DataFrame) -> DataFrame:
    """
    Surface select nested fields in a dataframe into own columns.
    Input: DF with nested fields
    Output: DF with new columns for the fields
    """
    # flatten ip_data
    ip_columns = df.apply(lambda row: map_ip_data(row['ip_data']), axis=1)
    df.drop(columns=['ip_data'], inplace=True)
    df = concat([df, ip_columns], axis=1)
    #
    return df

