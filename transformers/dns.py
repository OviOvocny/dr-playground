import datetime
import re
import tldextract
from pandas import DataFrame, Series, concat
from pandas.errors import OutOfBoundsDatetime

def dns(df: DataFrame) -> DataFrame:
    """
    Transform tls field into new columns.
    Input: DF with tls field
    Output: DF with new columns for the fields
    """
    
    #dns_columns = df.apply(find_derived_dns_features, axis=1)
    #df = concat([df, dns_columns], axis=1)
    df = df.apply(find_derived_dns_features, axis=1)
    return df


"""   
@param item: one tls field from database
@param collection_date: date when the collection was made
@return: return {"success": True/False, "features": dict/None}
"""  
def find_derived_dns_features(row: Series) -> Series:
    
    #['A', 'AAAA', 'CNAME', 'MX', 'NS', 'SOA', 'TXT']

    row["dns_soa_primary_ns_subdomains"] = None
    row["dns_soa_primary_ns_digit_count"] = None
    row["dns_soa_primary_ns_len"] = None

    row["dns_soa_admin_email_len"] = None
    row["dns_soa_admin_email_subdomains"] = None
    row["dns_soa_admin_email_digit_count"] = None

    row["domain_name_in_mx"] = 0
    row["dns_txt_google_vetified"] = 0

    domain_name = row["domain_name"]
    
    # SOA-related features
    if row["dns_SOA"] is not None and len(row["dns_SOA"]) > 0:
        parts = row["dns_SOA"][0].split()
        if len(parts) >= 1:
            primary_ns = parts[0]
            row["dns_soa_primary_ns_subdomains"] = primary_ns.count("\.")
            row["dns_soa_primary_ns_digit_count"] = sum([1 for d in primary_ns if d.isdigit()])
            row["dns_soa_primary_ns_len"] = len(primary_ns)
        if len(parts) >= 2:
            admin_email = parts[1]
            row["dns_soa_admin_email_subdomains"] = primary_ns.count("\.")
            row["dns_soa_admin_email_digit_count"] = sum([1 for d in primary_ns if d.isdigit()])
            row["dns_soa_admin_email_len"] = len(admin_email)
       
    # MX-related features
    if row["dns_MX"] is not None:
        for mailserver in row['dns_MX']:
            if domain_name in mailserver:
                row["domain_name_in_mx"] = 1
                break
    
    # Google site verification in TXT
    if row["dns_TXT"] is not None:
        for rec in row['dns_TXT']:
            if "google-site-verification" in rec:
                row["dns_txt_google_vetified"] = 1
                break
    
    return row
    