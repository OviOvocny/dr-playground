from pandas import DataFrame, Series, concat
from ._helpers import map_dict_to_series
import hashlib

def hash_text(input):
    return int(hashlib.md5(input.encode("ascii")).hexdigest(), 16) % 2147483647

def rdap(df: DataFrame) -> DataFrame:
    """
    TODO: document
    """

    # add rdap derived columns
    df['rdap_domain_registration_period'] = df['domain_expiration_date'] - df['domain_registration_date']
    #NOTUSED# df['rdap_domain_lifetime'] = min(df['dns_evaluated_on'], df['domain_expiration_date']) - df['domain_registration_date']
    #NOTUSED# df['rdap_domain_time_from_last_change'] = df['dns_evaluated_on'] - df['domain_last_changed_date']

    df["rdap_has_dnssec"] = df["rdap_dnssec"].astype("bool")
    
    #df = df.apply(add_rdap_detail_features, axis=1)

    return df


def add_rdap_detail_features(row: Series) -> Series:
    
    row["registrant_name_len"] = None
    row["registrant_name_hash"] = None

    row["administrative_name_len"] = None
    row["administrative_name_hash"] = None

    if "registrant" in row["rdap_entities"]:
        if "name" in row["rdap_entities"]["registrant"]:
            row["registrant_name_len"] = len(row["rdap_entities"]["registrant"])
            row["registrant_name_hash"] = hash_text(row["rdap_entities"]["registrant"]["name"])
    
    if "administrative" in row["rdap_entities"]:
        if "name" in row["rdap_entities"]["administrative"]:
            row["administrative_name_len"] = len(row["rdap_entities"]["administrative"])
            row["administrative_name_hash"] = hash_text(row["rdap_entities"]["administrative"]["name"])

    
    return row
    