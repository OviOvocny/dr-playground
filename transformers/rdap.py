from pandas import DataFrame, Series, concat
from ._helpers import map_dict_to_series
import hashlib

def hash_text(input):
    return int(hashlib.md5(input.encode("utf-8")).hexdigest(), 16) % 2147483647

def rdap(df: DataFrame) -> DataFrame:
    """
    TODO: document
    """

    # add rdap derived columns
    df['rdap_registration_period'] = df['rdap_expiration_date'] - df['rdap_registration_date']
    df['rdap_active_time'] = df['rdap_evaluated_on'] - df['rdap_registration_date']
    df['rdap_time_from_last_change'] = df['rdap_evaluated_on'] - df['rdap_last_changed_date']
    
    #NOTUSED# df['rdap_domain_lifetime'] = min(df['dns_evaluated_on'], df['domain_expiration_date']) - df['domain_registration_date']
    #NOTUSED# df['rdap_domain_time_from_last_change'] = df['dns_evaluated_on'] - df['domain_last_changed_date']

    df["rdap_has_dnssec"] = df["rdap_dnssec"].astype("bool")
    
    df["rdap_registrant_name_len"], df["rdap_registrant_name_hash"], \
    df["rdap_registrar_name_len"], df["rdap_registrar_name_hash"], \
    df["rdap_administrative_name_len"], df["rdap_administrative_name_hash"], \
    df["rdap_administrative_email_hash"] = zip(
        *df["rdap_entities"].apply(add_rdap_detail_features))

    return df


def add_rdap_detail_features(rdap_entities):
    if rdap_entities is None:
        return None, None, None, None, None, None, None

    registrant_name_len = 0
    registrant_name_hash = 0
    registrar_name_len = 0
    registrar_name_hash = 0
    administrative_name_len = 0
    administrative_name_hash = 0
    administrative_email_hash = 0

    if "registrant" in rdap_entities and rdap_entities["registrant"] is not None and len(rdap_entities["registrant"]) > 0:
        if "name" in rdap_entities["registrant"][0] and rdap_entities["registrant"][0]["name"] is not None:
            registrant_name_len = len(rdap_entities["registrant"][0]["name"])
            registrant_name_hash = hash_text(rdap_entities["registrant"][0]["name"])
    
    if "registrar" in rdap_entities and rdap_entities["registrar"] is not None and len(rdap_entities["registrar"]) > 0:
        if "name" in rdap_entities["registrar"][0] and rdap_entities["registrar"][0]["name"] is not None:
            registrar_name_len = len(rdap_entities["registrar"][0]["name"])
            registrar_name_hash = hash_text(rdap_entities["registrar"][0]["name"])

    if "administrative" in rdap_entities and rdap_entities["administrative"] is not None and len(rdap_entities["administrative"]) > 0:
        if "name" in rdap_entities["administrative"][0] and rdap_entities["administrative"][0]["name"] is not None:
            administrative_name_len = len(rdap_entities["administrative"][0]["name"])
            administrative_name_hash = hash_text(rdap_entities["administrative"][0]["name"])
        if "email" in rdap_entities["administrative"][0] and rdap_entities["administrative"][0]["email"] is not None:
            administrative_email_hash = hash_text(rdap_entities["administrative"][0]["email"])
        
    
    return registrant_name_len, registrant_name_hash, registrar_name_len, registrar_name_hash, administrative_name_len, administrative_name_hash, administrative_email_hash
    