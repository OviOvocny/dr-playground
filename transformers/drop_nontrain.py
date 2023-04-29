from pandas import DataFrame
import pyarrow as pa

nontraining_fields = [
    "domain_name",
    # drop remark fields - not intended for training, skews results
    "tls_evaluated_on",
    #"tls",
    "countries",
    "latitudes",
    "longitudes",
    *[f"dns_{t}" for t in ["A", "AAAA", "CNAME", "MX", "NS", "SOA", "TXT"]],
    "domain_registration_date",
    "domain_last_changed_date",
    "domain_expiration_date",
    "average_rtt",
    "rdap_dnssec"
]

def drop_nontrain(df):
    """
    Drop non-training columns.
    """
    return df.drop(nontraining_fields)
