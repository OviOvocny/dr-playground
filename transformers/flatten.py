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
    #
    # flatten remarks
    remarks_mapping = {
        "tls_evaluated_on": "tls_evaluated_on",
    }
    remarks_columns = df.apply(lambda row: map_dict_to_series(row['remarks'], remarks_mapping), axis=1)
    df.drop(columns=['remarks'], inplace=True)
    df = concat([df, remarks_columns], axis=1)
    #
    # flatten dns
    dns_mapping = { type: type for type in ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'SOA', 'TXT'] }
    dns_columns = df.apply(lambda row: map_dict_to_series(row['dns'], dns_mapping, prefix='dns_'), axis=1)
    df.drop(columns=['dns'], inplace=True)
    df = concat([df, dns_columns], axis=1)
    #
    # flatten rdap
    rdap_mapping = {
        "registration_date": "registration_date",
        "expiration_date": "expiration_date",
        "last_changed_date": "last_changed_date",
        #"registrar_handle": "entities.registrar.0.handle"
    }
    rdap_columns = df.apply(lambda row: map_dict_to_series(row['rdap'], rdap_mapping, prefix='domain_'), axis=1)
    df.drop(columns=['rdap'], inplace=True)
    df = concat([df, rdap_columns], axis=1)
    #
    # flatten ip_data
    ip_columns = df.apply(lambda row: map_ip_data(row['ip_data']), axis=1)
    df.drop(columns=['ip_data'], inplace=True)
    df = concat([df, ip_columns], axis=1)
    #
    return df

