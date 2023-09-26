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
    df['rdap_domain_age'] = df['rdap_evaluated_on'] - df['rdap_registration_date']
    df['rdap_time_from_last_change'] = df['rdap_evaluated_on'] - df['rdap_last_changed_date']
    df["rdap_domain_active_time"] = df[["dns_evaluated_on", "rdap_expiration_date"]].max(axis=1)  - df['rdap_registration_date']
    #NOTUSED# df['rdap_domain_time_from_last_change'] = df['dns_evaluated_on'] - df['domain_last_changed_date']

    df["rdap_has_dnssec"] = df["rdap_dnssec"].astype("bool")
    
    df["rdap_registrant_name_len"], df["rdap_registrant_name_hash"], \
    df["rdap_registrar_name_len"], df["rdap_registrar_name_hash"], \
    df["rdap_administrative_name_len"], df["rdap_administrative_name_hash"], \
    df["rdap_administrative_email_len"], df["rdap_administrative_email_hash"] = zip(
        *df["rdap_entities"].apply(get_rdap_domain_features)
    )

    df["ip_v4_count"], df["ip_v6_count"], df["rdap_ip_first_administrative_name_len"], df["rdap_ip_first_administrative_name_hash"], \
        df["rdap_ip_first_administrative_email_len"], df["rdap_ip_first_administrative_email_hash"], \
        df["rdap_ip_shortest_v4_prefix_len"], df["rdap_ip_longest_v4_prefix_len"], \
        df["rdap_ip_shortest_v6_prefix_len"], df["rdap_ip_longest_v6_prefix_len"] = zip(
            *df["ip_data"].apply(get_rdap_ip_features)
    )

    return df

def get_rdap_domain_features(rdap_entities):
    registrant_name_len = 0
    registrant_name_hash = 0
    registrar_name_len = 0
    registrar_name_hash = 0
    administrative_name_len = 0
    administrative_name_hash = 0
    administrative_email_len = 0
    administrative_email_hash = 0

    if rdap_entities is not None:
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
                administrative_email_hash = len(rdap_entities["administrative"][0]["email"])  
                administrative_email_hash = hash_text(rdap_entities["administrative"][0]["email"])    
    
    return registrant_name_len, registrant_name_hash, registrar_name_len, registrar_name_hash, administrative_name_len, administrative_name_hash, \
        administrative_email_len, administrative_email_hash

def get_rdap_ip_features(ip_data):
    ip_v4_count = 0
    ip_v6_count = 0

    # Relates to the first IP address where those fieds are not empty
    rdap_ip_first_administrative_name_len = 0
    rdap_ip_first_administrative_name_hash = 0
    rdap_ip_first_registrant_email_len = 0
    rdap_ip_first_registrant_email_hash = 0
    
    ip_shortest_v4_prefix_len = 0
    ip_longest_v4_prefix_len = 0
    ip_shortest_v6_prefix_len = 0
    ip_longest_v6_prefix_len = 0
    
    if ip_data is not None:
        for ip in ip_data:
            ip_address = ip["ip"]
            
            if ip["rdap"] is not None:
                # Examine IP and network information
                if ip["rdap"]["ip_version"] is not None:
                    ip_version = ip["rdap"]["ip_version"]
                    if ip_version == 4:
                        ip_v4_count += 1
                    else:
                        ip_v6_count += 1

                if ip["rdap"]["network"] is not None:
                    if ip["rdap"]["network"]["prefix_length"] is not None:
                        prefix_len = ip["rdap"]["network"]["prefix_length"]

                    if ip_version == 4: # IPv4
                        if ip_shortest_v4_prefix_len == 0:
                            ip_shortest_v4_prefix_len = prefix_len
                        if ip_longest_v4_prefix_len == 0:
                            ip_longest_v4_prefix_len = prefix_len
                        if prefix_len < ip_shortest_v4_prefix_len:
                            ip_shortest_v4_prefix_len = prefix_len
                        if prefix_len > ip_longest_v4_prefix_len:
                            ip_longest_v4_prefix_len = prefix_len
                    else: # IPv6
                        if ip_shortest_v6_prefix_len == 0:
                            ip_shortest_v6_prefix_len = prefix_len
                        if ip_longest_v6_prefix_len == 0:
                            ip_longest_v6_prefix_len = prefix_len
                        if prefix_len < ip_shortest_v6_prefix_len:
                            ip_shortest_v6_prefix_len = prefix_len
                        if prefix_len > ip_longest_v6_prefix_len:
                            ip_longest_v6_prefix_len = prefix_len

                # Examine RDAP entities
                if ip["rdap"]["entities"] is not None and len(ip["rdap"]["entities"]) > 0:
                    if "administrative" in ip["rdap"]["entities"] and ip["rdap"]["entities"]["administrative"] is not None and \
                    len(ip["rdap"]["entities"]["administrative"]) > 0:
                        if "name" in ip["rdap"]["entities"]["administrative"][0] and ip["rdap"]["entities"]["administrative"][0]["name"] is not None:
                            if rdap_ip_first_administrative_name_len == 0:
                                rdap_ip_first_administrative_name_len = len(ip["rdap"]["entities"]["administrative"][0]["name"])
                                rdap_ip_first_administrative_name_hash = hash_text(ip["rdap"]["entities"]["administrative"][0]["name"])
                        if "email" in ip["rdap"]["entities"]["administrative"][0] and ip["rdap"]["entities"]["administrative"][0]["email"] is not None:
                            if rdap_ip_first_registrant_email_len == 0:
                                rdap_ip_first_registrant_email_len = len(ip["rdap"]["entities"]["administrative"][0]["email"])
                                rdap_ip_first_registrant_email_hash = hash_text(ip["rdap"]["entities"]["administrative"][0]["email"])
            
    return ip_v4_count, ip_v6_count, rdap_ip_first_administrative_name_len, rdap_ip_first_administrative_name_hash, \
        rdap_ip_first_registrant_email_len, rdap_ip_first_registrant_email_hash, \
        ip_shortest_v4_prefix_len, ip_longest_v4_prefix_len, ip_shortest_v6_prefix_len, ip_longest_v6_prefix_len
        