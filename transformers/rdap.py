from pandas import DataFrame, Series, concat
from ._helpers import map_dict_to_series


def rdap(df: DataFrame) -> DataFrame:
    """
    TODO: document
    """

    # add rdap derived columns
    df['rdap_domain_registration_period'] = df['domain_expiration_date'] - df['domain_registration_date']
    #NOTUSED# df['rdap_domain_lifetime'] = df['dns_evaluated_on'] - df['domain_registration_date']
    #NOTUSED# df['rdap_domain_time_from_last_change'] = df['dns_evaluated_on'] - df['domain_last_changed_date']

    df["rdap_has_dnssec"] = df["rdap_dnssec"].astype("bool")

    return df