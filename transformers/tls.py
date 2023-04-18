import datetime
import re
from pandas import DataFrame, Series, concat

def run_analyzer(row: Series) -> Series:
    """
    Run all analyzers on the row.
    """
    tls = row["tls"]
    date = row["tls_evaluated_on"]
    analysis_result = analyze_tls(tls, date)
    return Series(analysis_result['features'])

def tls(df: DataFrame) -> DataFrame:
    """
    Transform tls field into new columns.
    Input: DF with tls field
    Output: DF with new columns for the fields
    """
    tls_columns = df.apply(run_analyzer, axis=1)
    df.drop(columns=['tls'], inplace=True)
    df = concat([df, tls_columns], axis=1)
    return df




security_scores = {
    "TLSv1.0": 0,
    "TLSv1.1": 1,
    "TLSv1.2": 2,
    "TLSv1.3": 3
}

cipher_scores = {
    'ECDHE-RSA-AES128-GCM-SHA256': 0,
    'TLS_AES_128_GCM_SHA256': 1,
    'TLS_AES_256_GCM_SHA384': 2,
    'ECDHE-ECDSA-CHACHA20-POLY1305': 3,
    'ECDHE-RSA-AES128-SHA': 3,
    'ECDHE-RSA-CHACHA20-POLY1305': 4,
    'ECDHE-RSA-AES256-GCM-SHA384': 5,
    'ECDHE-ECDSA-AES128-GCM-SHA256': 6,
    'TLS_CHACHA20_POLY1305_SHA256': 7,
    'ECDHE-ECDSA-AES256-GCM-SHA384': 8,
    'ECDHE-RSA-AES256-SHA384': 9,
    'AES128-SHA256': 10,
    'DHE-RSA-AES256-GCM-SHA384': 11,
    'AES256-SHA256': 12,
    'AES128-SHA': 13,
    'DHE-RSA-AES128-GCM-SHA256': 14
}

"""   
@param item: one tls field from database
@param collection_data: date when the collection was made
@return: return {"success": True/False, "features": dict/None}
"""  
def analyze_tls(item: dict, collection_data: datetime.datetime) -> dict:
    # We dont hane tls data for this domain
    if item is None:
        features = { 
            "has_tls": False,
            "chain_len": None,
                "tls_version_score": None,                 # Evaluated TLS version
                "cipher_score": None,                           # Evaluated cipher
                "root_crt_validity__len": None,       # Total validity time of root certificate
                "root_crt_time_to_expire": None,     # Time to expire of root certificate from time of collection
                "leaf_crt_validity_len": None,         # Total validity time of leaf certificate      
                "leaf_cert_time_to_live": None,       # Time to expire of leaf certificate from time of collection      
                "mean_cert_len": None,                         # Mean validity time of all certificates in chain including root
                "broken_chain": None,                           # Chain was never valid, 
                "expired_chain": None,                         # Chain already expired at time of collection
                "total_extension_count": None,         # Total number of extensions in certificate
                "critical_extensions": None,             # Total number of critical extensions in certificate
                "have_policies": None,                         # Number of certificates enforcing specific encryption policy
                "percentage_of_policies": None,       # Percentage of certificates enforcing specific encryption policy
                "unknown_usage": None,                         # How many cerificates uses unknown (not X509v3, not version 1, not version 2) policy
                "X_509_used_cnt": None,                       # Number of certificates enforcing X509v3 policy
                "version_2_used_cnt": None,               # Number of certificates enforcing version 2 policy
                "version_1_used_cnt": None,               # Number of certificates enforcing version 1 policy
                "subject_count": None,                         # How many subjects can be found in SAN extension ( can be linked to phishing)       
                "server_auth": None,                             # How many certificates are used for server authentication (can be simultanously used for client authentication)      
                "client_auth": None,                             # How many certificates are used for client authentication
                "CA_count": None,                                   # Count of certificates that are also CA (can sign other certificates)
                "CA_ratio": None                                    # Ration of CA certificates in chain
                }
    
        return {"success": False, "features": features}
    
    SSL_SCORE = 0
        
    # FEATURES
    tls_version_score = security_scores.get(item['protocol'] , 0)
    cipher_score = cipher_scores.get(item['cipher'] , 0)
    
    # Certificate features #
    
    
    ### ROOT CERTIFICATE ###
    root_crt_validity__len = -1
    root_crt_time_to_expire = -1
    
    
    ### LEAF CERTIFICATE ###
    leaf_crt_validity_len = -1
    leaf_cert_time_to_live = -1
    
    
    ### BAIC FEATURES ###
    mean_cert_len = -1
    broken_chain = 0
    expired_chain = 0
    
    
    ### EXTENSION FEATURES ###
    total_extension_count = -1
    critical_extensions = -1
    have_policies = 0
    percentage_of_policies = 0
    server_auth = 0
    client_auth = 0
    unknown_usage = 0
    X_509_used_cnt = 0
    version_2_used_cnt = 0
    version_1_used_cnt = 0
    CA_count = 0  # Ration of CA certificates in chain
    CA_ratio = 0
    
    ### NUMBER OF SUBJECTS if SAN ###
    subject_count = 0

    #### Procesing of certificates and root especialy ####
    if len(item['certificates']) == 0:
        return {"success": False, "error": "No certificates"}
    mean_len = 0
    cert_counter = 0
    for certificate in item['certificates']: 
        cert_counter += 1
        
        validity_len = round(int(certificate['valid_len']) / (60*60*24))
        
        if validity_len < 0:
            broken_chain = 1
            break
        
        
        time_to_expire = certificate['validity_end'] - collection_data
        time_to_expire = round(time_to_expire.total_seconds() / (60*60*24))
        
        if time_to_expire < 0:
            expired_chain = 1
            break
            
    
        if cert_counter == 1:
            leaf_cert_time_to_live = time_to_expire
            leaf_crt_validity_len = validity_len
            
        if certificate['is_root']:
            root_crt_time_to_expire = time_to_expire
            root_crt_validity__len = validity_len
        
            
        
            # if the certificate is not valid now it is suspicious
        mean_len += validity_len  

        mean_cert_len = mean_len / cert_counter
        
        
        #### EXTENSIONS ####
        total_extension_count = certificate['extension_count']
        for extension in certificate['extensions']:
            if extension['critical']:
                critical_extensions += 1
                
                
            if extension['name'] == "subjectAltName":
                subject_count = len(extension['value'].split(","))
                
            
                            
            if extension["name"] == "extendedKeyUsage":
                # apend extension [value] to file issuers.txt
                auth_type = extension["value"].split(", ")
                
                for auth in auth_type:
                    if auth == "TLS Web Server Authentication":
                        server_auth += 1
                    if auth == "TLS Web Client Authentication":
                        client_auth += 1    
                        
            if extension["name"] == "certificatePolicies":
                have_policies += 1
                data = extension["value"].split(",")
                
                # for each value remove everythong after newline 
                data = [x.split("\n")[0] for x in data]
                # filter values starting only with Policy:
                data = list(filter(lambda x: x.startswith("Policy:"), data))
                
                
                for policy in data:
                            
                    # match regex to policy
                    if re.compile(r"(.)*X509v3(.)*").match(policy):
                        X_509_used_cnt += 1
                    elif re.compile(r"Policy: 1\.").match(policy):
                        version_1_used_cnt += 1
                    elif re.compile(r"Policy: 2\.").match(policy):
                        version_2_used_cnt += 1
            
            if extension["name"] == "basicConstraints":
                if extension["value"] == "CA:TRUE":
                    CA_count += 1
                




    # computation of certificate chain fetures
    percentage_of_policies  = (have_policies / cert_counter)
    CA_ratio = (CA_count / cert_counter)
    
    
    ### roud float valuet to 1 decimal place ###
    mean_cert_len = round(mean_cert_len, 1)
    #CA_ratio = round(CA_ratio, 1)
    #percentage_of_policies = round(percentage_of_policies, 1)
    
        

        
        
    # Return dictionary with all features
    features = { 
                "has_tls": True,                                           # Has TLS
                "chain_len": item['count'],                                # Length of certificate chain
                "tls_version_score": tls_version_score,                 # Evaluated TLS version
                "cipher_score": cipher_score,                           # Evaluated cipher
                "root_crt_validity__len": root_crt_validity__len,       # Total validity time of root certificate
                "root_crt_time_to_expire": root_crt_time_to_expire,     # Time to expire of root certificate from time of collection
                "leaf_crt_validity_len": leaf_crt_validity_len,         # Total validity time of leaf certificate      
                "leaf_cert_time_to_live": leaf_cert_time_to_live,       # Time to expire of leaf certificate from time of collection      
                "mean_cert_len": mean_cert_len,                         # Mean validity time of all certificates in chain including root
                "broken_chain": broken_chain,                           # Chain was never valid, 
                "expired_chain": expired_chain,                         # Chain already expired at time of collection
                "total_extension_count": total_extension_count,         # Total number of extensions in certificate
                "critical_extensions": critical_extensions,             # Total number of critical extensions in certificate
                "have_policies": have_policies,                         # Number of certificates enforcing specific encryption policy
                "percentage_of_policies": percentage_of_policies,       # Percentage of certificates enforcing specific encryption policy
                "unknown_usage": unknown_usage,                         # How many cerificates uses unknown (not X509v3, not version 1, not version 2) policy
                "X_509_used_cnt": X_509_used_cnt,                       # Number of certificates enforcing X509v3 policy
                "version_2_used_cnt": version_2_used_cnt,               # Number of certificates enforcing version 2 policy
                "version_1_used_cnt": version_1_used_cnt,               # Number of certificates enforcing version 1 policy
                "subject_count": subject_count,                         # How many subjects can be found in SAN extension ( can be linked to phishing)       
                "server_auth": server_auth,                             # How many certificates are used for server authentication (can be simultanously used for client authentication)      
                "client_auth": client_auth,                             # How many certificates are used for client authentication
                "CA_count": CA_count,                                   # Count of certificates that are also CA (can sign other certificates)
                "CA_ratio": CA_ratio                                    # Ration of CA certificates in chain

                }
    
    return {"success": True, "features": features}