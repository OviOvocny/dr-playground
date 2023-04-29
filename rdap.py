from pandas import DataFrame, Series, concat
from ._helpers import map_dict_to_series


def rdap(df: DataFrame) -> DataFrame:
    """
    TODO: document
    """

    # add rdap derived columns
    df['domain_registration_period'] = df['domain_expiration_date'] - df['domain_registration_date']
    df['domain_lifetime'] = df['dns_evaluated_on'] - df['domain_registration_date']
    df['domain_time_from_last_change'] = df['dns_evaluated_on'] - df['domain_last_changed_date']

    df.drop(columns=['domain_registration_date', 'domain_last_changed_date', 'domain_expiration_date'], inplace=True)
    return df