from typing import Optional
import json
import numpy as np
from pandas import DataFrame, Series
from dns.name import from_text as name_from_text
from ._helpers import get_normalized_entropy
import schema
import cProfile


def dns(df: DataFrame) -> DataFrame:
    """
    Transform the tls field into new columns and add ngram matches.
    Input: DataFrame with tls field, ngram frequency dictionary
    Output: DataFrame with new columns for the fields
    """

    profiler = cProfile.Profile()

    # get ngram frequency dictionary from json file ngam_freq.json
    with open('ngram_freq.json') as f:
        ngram_freq = json.load(f)

    profiler.enable()
    df = add_dns_record_counts(df)
    df = df.apply(find_derived_dns_features, args=(ngram_freq,), axis=1)
    profiler.disable()
    profiler.dump_stats("dns.stats")

    return df


def add_dns_record_counts(df: DataFrame) -> DataFrame:
    """
    Calculate number of DNS records for each domain.
    Input: DF with dns_* columns
    Output: DF with dns_*_count columns added
    """

    for column in [f'dns_{c}' for c in ['A', 'AAAA', 'MX', 'NS', 'TXT']]:
        df[column + '_count'] = df[column].apply(lambda values: len(values) if values is not None else 0)

    df["dns_SOA_count"] = 0 if df["dns_SOA"] is None else 1
    df["dns_CNAME_count"] = 0 if df["dns_CNAME"] is None else 1

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
            matches += 1
    return matches


def make_dnssec_score(row: Series) -> Optional[float]:
    dnssec = row["dns_dnssec"]
    if dnssec is None:
        row.drop(["dns_dnssec"], inplace=True)
        return None

    # only consider record types that have been resolved for the dn
    values = [v for (k, v) in dnssec.items() if (row[f"dns_{k}_count"] or 0) > 0]
    score = 0.0

    if 1 in values:
        # at least one valid signature
        # 0 -> -1, 2 -> -2
        for v in values:
            if v == 1:
                score += 1.0
            elif v == 0:
                score -= 1.0
            elif v == 2:
                score -= 2.0
    else:
        # no valid signature, score will be -1
        score = -len(values)

    row.drop(["dns_dnssec"], inplace=True)
    return score / len(values)


def count_resolved_record_types(row: Series) -> int:
    ret = 0
    for record_type in schema.dns_types_all:
        if row[f"dns_{record_type}"] is not None:
            ret += 1
    return ret


def make_ttl_features(row: Series):
    (row["dns_ttl_mean"], row["dns_ttl_stdev"],
     row["dns_ttl_low"], row["dns_ttl_mid"]) = (None, None, None, None)

    ttls = row["dns_ttls"]
    if ttls is None:
        row.drop(["dns_ttls"], inplace=True)
        return

    ttls = np.array([v for v in ttls.values() if v is not None])
    if len(ttls) == 0:
        row.drop(["dns_ttls"], inplace=True)
        return

    row["dns_ttl_mean"] = np.mean(ttls)
    row["dns_ttl_stdev"] = np.std(ttls)

    bins = [101, 501]
    bin_counts = np.bincount(np.digitize(ttls, bins))
    total_vals = len(ttls)

    row["dns_ttl_low"] = bin_counts[0] / total_vals if len(bin_counts) > 0 else 0
    row["dns_ttl_mid"] = bin_counts[1] / total_vals if len(bin_counts) > 1 else 0

    row["dns_ttl_distinct_count"] = len(np.unique(ttls))

    row.drop(["dns_ttls"], inplace=True)


def make_mx_features(row: Series):
    row["dns_mx_mean_len"] = None
    row["dns_mx_mean_entropy"] = None
    row["dns_domain_name_in_mx"] = 0

    domain_name = row["domain_name"]
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


def make_soa_features(row: Series):
    prepare_dn_string_features(row, "soa_primary_ns")
    prepare_dn_string_features(row, "soa_admin_email")
    row["dns_soa_serial"] = None
    row["dns_soa_refresh"] = None
    row["dns_soa_retry"] = None
    row["dns_soa_expire"] = None
    row["dns_soa_min_ttl"] = None

    soa = row["dns_SOA"]
    # only consider zone SOA if it's not a SOA of a TLD
    if soa is None and row["dns_zone"] is not None and row["dns_zone_level"] > 2:
        soa = row["dns_zone_SOA"]

    if soa is not None:
        primary_ns = soa["primary_ns"]
        make_dn_string_features(row, "soa_primary_ns", primary_ns)

        admin_email = soa["resp_mailbox_dname"]
        make_dn_string_features(row, "soa_admin_email", admin_email)

        # flattening
        row["dns_soa_serial"] = soa["serial"]
        row["dns_soa_refresh"] = soa["refresh"]
        row["dns_soa_retry"] = soa["retry"]
        row["dns_soa_expire"] = soa["expire"]
        row["dns_soa_min_ttl"] = soa["min_ttl"]

    row.drop(["dns_SOA", "dns_zone_SOA"], inplace=True)


def prepare_dn_string_features(row: Series, feature_name_base: str):
    row[f"dns_{feature_name_base}_level"] = None
    row[f"dns_{feature_name_base}_digit_count"] = None
    row[f"dns_{feature_name_base}_len"] = None
    row[f"dns_{feature_name_base}_entropy"] = None


def make_dn_string_features(row: Series, feature_name_base: str, dn: str):
    domain_name = name_from_text(dn)
    row[f"dns_{feature_name_base}_level"] = len(domain_name) - 1
    row[f"dns_{feature_name_base}_digit_count"] = sum([1 for d in dn if d.isdigit()])
    row[f"dns_{feature_name_base}_len"] = len(dn)
    row[f"dns_{feature_name_base}_entropy"] = get_normalized_entropy(dn)


def make_txt_features(row: Series):
    # TXT-derived features
    row["dns_txt_mean_entropy"] = None
    row["dns_txt_external_verification_score"] = 0

    txt_entropy_sum = 0
    verification_score = 0
    verifiers = ("google-site-verification=", "ms=", "apple-domain-verification=",
                 "facebook-domain-verification=")
    total_non_empty = 0

    if row["dns_TXT"] is not None and len(row["dns_TXT"]) > 0:
        for rec in row['dns_TXT']:
            if len(rec) == 0:
                continue

            total_non_empty += 1
            txt_entropy_sum += get_normalized_entropy(rec)

            rec = str(rec).lower()
            for verifier in verifiers:
                if verifier in rec:
                    verification_score += 1

        if txt_entropy_sum > 0:
            row["dns_txt_mean_entropy"] = txt_entropy_sum / total_non_empty

        row["dns_txt_external_verification_score"] = verification_score


def find_derived_dns_features(row: Series, ngram_freq: dict) -> Series:
    domain_name = name_from_text(row["domain_name"])

    # DN level
    row["dns_dn_level"] = len(domain_name) - 1
    row["dns_distance_from_zone"] = row["dns_dn_level"]
    prepare_dn_string_features(row, "zone")

    if row["dns_zone"] is not None:
        make_dn_string_features(row, "zone", row["dns_zone"])
        row["dns_distance_from_zone"] = row["dns_dn_level"] - row["dns_zone_level"]

    # Total number of record types resolved for the DN
    row["dns_record_type_count"] = count_resolved_record_types(row)

    # DNSSEC
    row["dns_has_dnskey"] = 1 if row["dns_has_dnskey"] else 0
    if row["dns_has_dnskey"]:
        row["dns_dnssec_score"] = make_dnssec_score(row)
    else:
        row["dns_dnssec_score"] = 0.0

    # TTL
    make_ttl_features(row)

    # SOA-derived features
    make_soa_features(row)

    # MX-derived features
    make_mx_features(row)

    # TXT features
    make_txt_features(row)

    # E-mail/TXT features (flattening)
    row["dns_txt_spf_exists"] = 1 if row["dns_email_extras"]["spf"] else 0
    row["dns_txt_dkim_exists"] = 1 if row["dns_email_extras"]["dkim"] else 0
    row["dns_txt_dmarc_exists"] = 1 if row["dns_email_extras"]["dmarc"] else 0
    row.drop(["dns_email_extras"], inplace=True)

    # Calculate ngram matches, find if bigram or trigram of this domain name is present in the ngram list
    row["dns_bigram_matches"] = 0
    row["dns_trigram_matches"] = 0

    domain_name = row["domain_name"]
    if domain_name is not None:
        row["dns_bigram_matches"] += find_ngram_matches(domain_name, ngram_freq["bigram_freq"])
        row["dns_trigram_matches"] += find_ngram_matches(domain_name, ngram_freq["trigram_freq"])

    return row
