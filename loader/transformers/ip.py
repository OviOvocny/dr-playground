import ipaddress

from pandas import DataFrame, Series

from ._helpers import mean_of_existing_values
import pandas as pd
import numpy as np


def make_entropy(data):
    # get unique values and their counts
    _, counts = np.unique(data, return_counts=True)
    # calculate probabilities
    probs = counts / counts.sum()
    # calculate entropy
    return -np.sum(probs * np.log2(probs))


def ip_entropy(values) -> float:
    if values is None:
        return 0.0

    prefixes4 = []
    prefixes6 = []

    for ip_entry in values:
        ip = ip_entry["ip"]
        if ':' not in ip:
            parts = ip.split('.')[:2]
            prefix = int(parts[0]) * 256 + int(parts[1])
            prefixes4.append(prefix)
        else:
            ip_obj = ipaddress.IPv6Address(ip)
            prefix = int.from_bytes(ip_obj.packed[:8], "big")
            prefixes6.append(prefix)

    entropy4 = make_entropy(prefixes4)
    entropy6 = make_entropy(prefixes6)
    return entropy4 + entropy6


def make_asn_features(ip_data):
    if ip_data is None:
        return None, None, None

    asns = []
    dist_asns = set()
    prefixes4 = []
    prefixes6 = []

    for ip_entry in ip_data:
        asn = ip_entry["asn"]
        if asn is None:
            continue

        asns.append(asn["asn"])
        dist_asns.add(asn["asn"])
        ip = asn["network_address"]
        if ':' not in ip:
            prefixes4.append(int.from_bytes(ipaddress.IPv4Address(ip).packed, "big"))
        else:
            prefixes6.append(int.from_bytes(ipaddress.IPv6Address(ip).packed, "big"))

    if len(asns) == 0:
        return None, None, None

    as_address_entropy = make_entropy(prefixes4) + make_entropy(prefixes6)
    asn_entropy = make_entropy(asns)
    distinct_as_count = len(dist_asns)

    return as_address_entropy, asn_entropy, distinct_as_count


def ip(df: DataFrame) -> DataFrame:
    df["ip_count"] = df["ip_data"].apply(lambda x: len(x) if x is not None else 0)
    df["ip_mean_average_rtt"] = df["ip_data"].apply(
        lambda ip_data: mean_of_existing_values(
            [ip['remarks']['average_rtt'] for ip in ip_data]) if ip_data is not None else 0)

    # ratio between A/AAAA records count and all related IPs count
    df["ip_a_ratio"] = df.apply(
        lambda row: 0 if row["ip_count"] == 0 else (row["dns_A_count"] + row["dns_AAAA_count"]) / row["ip_count"],
        axis=1)

    # calculate entropy for each domain
    df['ip_entropy'] = df['ip_data'].apply(ip_entropy)

    # add features based on autonomous system information
    df["ip_as_address_entropy"], df["ip_asn_entropy"], df["ip_distinct_as_count"] = zip(
        *df["ip_data"].apply(make_asn_features))

    return df
