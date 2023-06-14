import datetime
import re
import tldextract
import math
from pandas import DataFrame, Series, concat
from pandas.errors import OutOfBoundsDatetime
from typing import Optional
import json
from nltk import ngrams, FreqDist
import pandas as pd

def add_dns_record_counts(df: DataFrame) -> DataFrame:
    """
    Calculate number of DNS records for each domain.
    Input: DF with dns_* columns
    Output: DF with dns_*_count columns added
    """

    for column in [f'dns_{c}' for c in ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'SOA', 'TXT']]:
        df[column + '_count'] = df[column].apply(lambda values: len(values) if values is not None else 0)
    return df

# Calculate ngram matches, find if bigram or trigram of this domain name is present in the ngram list
def find_ngram_matches(text: str, ngrams: dict) -> int:
    """
    Find the number of ngram matches in the text.
    Input: text string, ngrams dictionary
    Output: number of matches
    """
    matches = 0
    for ngram in ngrams:
        if ngram in text:
            print(ngram)
            matches += 1
    return matches

def dns(df: DataFrame, ngram_freq: dict) -> DataFrame:
    """
    Transform the tls field into new columns and add ngram matches.
    Input: DataFrame with tls field, ngram frequency dictionary
    Output: DataFrame with new columns for the fields
    """
    df = add_dns_record_counts(df)
    df = df.apply(find_derived_dns_features, args=(ngram_freq,), axis=1)
    return df

def get_normalized_entropy(text: str) -> Optional[float]:
    """Function returns the normalized entropy of the
    string. The function first computes the frequency
    of each character in the string using
    the collections.Counter function.
    It then uses the formula for entropy to compute
    the entropy of the string, and normalizes it by
    dividing it by the maximum possible entropy
    (which is the logarithm of the minimum of the length
    of the string and the number of distinct characters
    in the string).

    Args:
        domain (str): domain string

    Returns:
        float: normalized entropy
    """
    text_len = len(text)
    if text_len == 0:
        return None

    freqs = {}
    for char in text:
        if char in freqs:
            freqs[char] += 1
        else:
            freqs[char] = 1

    entropy = 0.0
    for f in freqs.values():
        p = float(f) / text_len
        entropy -= p * math.log(p, 2)
    return entropy / text_len

"""   
@param item: one tls field from database
@param collection_date: date when the collection was made
@return: return {"success": True/False, "features": dict/None}
"""  
def find_derived_dns_features(row: Series, ngram_freq: dict) -> Series:
    
    #['A', 'AAAA', 'CNAME', 'MX', 'NS', 'SOA', 'TXT']
    
    # SOA-derived features
    row["dns_soa_primary_ns_len"] = None
    row["dns_soa_primary_ns_subdomain_count"] = None
    row["dns_soa_primary_ns_digit_count"] = None
    row["dns_soa_primary_ns_entropy"] = None
    row["dns_soa_admin_email_len"] = None
    row["dns_soa_admin_email_subdomain_count"] = None
    row["dns_soa_admin_email_digit_count"] = None
    row["dns_soa_admin_email_entropy"] = None
    row["dns_soa_serial"] = None
    row["dns_soa_refresh"] = None
    row["dns_soa_retry"] = None
    row["dns_soa_expire"] = None
    row["dns_soa_neg_resp_caching_ttl"] = None

    # MX-derived features
    row["dns_mx_mean_len"] = None
    row["dns_mx_mean_entropy"] = None
    row["dns_domain_name_in_mx"] = 0

    # TXT-derived features
    row["dns_txt_google_verified"] = 0
    row["dns_txt_spf_exists"] = 0
    row["dns_txt_mean_entropy"] = None

    # Ngram features
    row["dns_bigram_matches"] = 0
    row["dns_trigram_matches"] = 0

    domain_name = row["domain_name"]

    # SOA-related features
    if row["dns_SOA"] is not None and len(row["dns_SOA"]) > 0:
        parts = row["dns_SOA"][0].split()
        if len(parts) >= 1:
            primary_ns = parts[0]
            row["dns_soa_primary_ns_subdomain_count"] = primary_ns.count('.')
            row["dns_soa_primary_ns_digit_count"] = sum([1 for d in primary_ns if d.isdigit()])
            row["dns_soa_primary_ns_len"] = len(primary_ns)
            row["dns_soa_primary_ns_entropy"] = get_normalized_entropy(primary_ns)
        if len(parts) >= 2:
            admin_email = parts[1]
            row["dns_soa_admin_email_subdomain_count"] = admin_email.count('.')
            row["dns_soa_admin_email_digit_count"] = sum([1 for d in primary_ns if d.isdigit()])
            row["dns_soa_admin_email_len"] = len(admin_email)
            row["dns_soa_admin_email_entropy"] = get_normalized_entropy(admin_email)
        if len(parts) >= 3:
            try:
                row["dns_soa_serial"] = int(parts[2])
            except:
                pass
        if len(parts) >= 4:
            try:
                row["dns_soa_refresh"] = int(parts[3])
            except:
                pass
        if len(parts) >= 5:
            try:
                row["dns_soa_retry"] = int(parts[4])
            except:
                pass
        if len(parts) >= 6:
            try:
                row["dns_soa_expire"] = int(parts[5])
            except:
                pass
        if len(parts) >= 7:
            try:
                row["dns_soa_neg_resp_caching_ttl"] = int(parts[6])
            except:
                pass

    # MX-related features
    mx_len_sum = 0
    mx_entropy_sum = 0
    if row["dns_MX"] is not None and len(row["dns_MX"]) > 0:
        for mailserver in row['dns_MX']:
            mx_len_sum += len(mailserver)
            mx_entropy_sum += get_normalized_entropy(mailserver)
            if domain_name in mailserver:
                row["dns_domain_name_in_mx"] = 1
                break
        if mx_len_sum > 0:
            row["dns_mx_mean_len"] = mx_len_sum / len(row["dns_MX"])
        if mx_entropy_sum > 0:
            row["dns_mx_mean_entropy"] = mx_entropy_sum / len(row["dns_MX"])

    # Google site verification in TXT
    txt_entropy_sum = 0
    if row["dns_TXT"] is not None and len(row["dns_TXT"]) > 0:
        for rec in row['dns_TXT']:
            txt_entropy_sum += get_normalized_entropy(rec)
            if "google-site-verification" in rec:
                row["dns_txt_google_verified"] = 1
            if "spf" in rec:
                row["dns_txt_spf_exists"] = 1
        if txt_entropy_sum > 0:
            row["dns_txt_mean_entropy"] = txt_entropy_sum / len(row["dns_TXT"])

    # Calculate ngram matches, find if bigram or trigram of this domain name is present in the ngram list
    if domain_name is not None:
        row["dns_bigram_matches"] += find_ngram_matches(domain_name, ngram_freq["bigram_freq"])
        row["dns_trigram_matches"] += find_ngram_matches(domain_name, ngram_freq["trigram_freq"])

    return row

