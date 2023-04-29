from pandas import DataFrame

import numpy as np

import math
import tldextract

phishing_keywords = {
    "account", "action", "alert", "app", "auth", "bank", "billing", "center", "chat", "device", "fax", "event",
    "find", "free", "gift", "help", "info", "invoice", "live", "location", "login", "mail", "map", "message",
    "my", "new", "nitro", "now", "online", "pay", "promo", "real", "required", "safe", "secure", "security",
    "service", "signin", "support", "track", "update", "verification", "verify", "vm", "web"
}

def longest_consonant_seq(domain: str) -> int:
    """Function returns longest consonant sequence

    Args:
        domain (str): domain name

    Returns:
        int: length of the longest consonant sequence
    """
    consonants = "bcdfghjklmnpqrstvwxyz"
    current_len = 0
    max_len = 0
    domain = domain.lower()
    for char in domain:
        if char in consonants:
            current_len += 1
        else:
            current_len = 0
        if current_len > max_len:
            max_len = current_len
    return max_len

def get_consonant_ratio(domain: str) -> float:
    """Function returns the consonant ratio
    which represents the total amount of consonants
    divided by the string length

    Args:
        domain (str): domain 

    Returns:
        float: consonant ratio
    """
    domain = domain.lower()
    consonants = set("bcdfghjklmnpqrstvwxyz")
    consonant_count = sum( 1 for char in domain if char in consonants )
    domain_len = len(domain)
    return consonant_count / domain_len if consonant_count > 0 else 0.0

def get_hex_ratio(domain: str) -> float:
    """Function computes hexadecimal ratio

    Args:
        domain (str): The length of the domain

    Returns:
        float: hexadecimal ratio
    """
    hex_chars = set('0123456789ABCDEFabcdef')
    hex_count = sum(char in hex_chars for char in domain)
    return hex_count / len(domain)


def get_normalized_entropy(domain: str) -> float:
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
    domain_len = len(domain)
    if domain_len == 0:
        return None

    freqs = {}
    for char in domain:
        if char in freqs:
            freqs[char] += 1
        else:
            freqs[char] = 1
    
    entropy = 0.0
    for f in freqs.values():
        p = float(f) / domain_len
        entropy -= p * math.log(p, 2)
    return entropy / domain_len

def contains_www(domain: str) -> int:
    """
    Function returns whether the domain contains
    the www subdomain. If the last subdomain is 'www'
    function returns 1, Otherwise function returns 0

    Args:
        domain (str): The whole domain name

    Returns:
        int: 1 if the domain name contains 'www'
             0 if the domain name does not contain 'www'
    """
    subdomains = domain.split(".")
    if subdomains[0] == "www":
        return 1
    return 0

def count_subdomains(domain:str) -> int:
    """
    Function returns the number of subdomains
    in the domain name 

    Args:
        domain (str): The domain name

    Returns:
        int: Number of subdomains
    """
    ext = tldextract.extract(domain)
    if not ext.subdomain:
        return 0

    else:
        subdomains = ext.subdomain.split(".")
        subdomains_count = len(subdomains)
        if "www" in subdomains:
            subdomains_count -= 1
        return subdomains_count

def verify_tld(domain_suffix:str, known_tlds:set) -> int:
    """
    Function checks whether the domain tld is in 
    the public suffix database

    Args:
        domain_suffix (str): Domain tld
        known_tlds (set): The set of the known tlds

    Returns:
        int: 1 if the tld is well-known
             0 if the tld is not well-known
    """
    if domain_suffix in known_tlds:
        return 1
    else:
        return 0

def remove_tld(domain: str) -> str:
    """Function removes tld from
    the domain name

    Args:
        domain (str): Domain name

    Returns:
        str: Domain without TLD
    """
    ext =  tldextract.extract(domain)
    subdomain = ext.subdomain
    sld = ext.domain
    result = subdomain + "." + sld if subdomain else sld
    return result

def extract_subdomains(domain:str) -> list:
    """
    Function returns the list of the subdomains and 
    sld from domain name

    Args:
        domain (str): The domain name

    Returns:
        list: Subdomains not including tld
    """
    ext = tldextract.extract(domain)
    subdomains = ext.subdomain.split('.') if ext.subdomain else []
    if 'www' in subdomains:
        subdomains.remove('www')
    sld = ext.domain
    domain_list = subdomains + [sld]
    return domain_list

def find_longest_word(char_sequence:str) -> list:
    """
    Function find the longest valid English word
    in a given sequence of characters.

    Args:
    - char_sequence (str): Input sequence of characters

    Returns:
    - str: Longest valid English word found in the input sequence
    """
    matched_words = []
    word = ""
    longest_word = None
    # If the empty string is passed
    if not char_sequence:
        return 
    
    # Iterate thorugh string 
    for char in char_sequence:
        word += char
        if word in english_words:
            matched_words.append(word)

    if matched_words:
        longest_word = max(matched_words, key=len)
        if longest_word:
            if (len(char_sequence) - len(longest_word)) > 0:
                find_longest_word(char_sequence.replace(longest_word, ""))
    else:
        find_longest_word(char_sequence[1:])
    print(longest_word)
    return longest_word
    
def find_longest_matched_words(char_sequence: str) -> list:
    """
    Function finds the longest valid English word(s)
    in a given sequence of characters.

    Args:
    - char_sequence (str): Input sequence of characters
    - english_words (set): Set of valid English words

    Returns:
    - list: List of longest matched English words found in the input sequence
    """
    matched_words = []
    word = ""
    longest_matched_words = []
    
    if not char_sequence:
        return longest_matched_words
    
    for char in char_sequence:
        word += char
        if word in english_words and len(word) > 1:
            matched_words.append(word)

    if matched_words:
        longest_word_length = max(len(word) for word in matched_words)
        longest_matched_words = [word for word in matched_words if len(word) == longest_word_length]
        if len(char_sequence) - longest_word_length > 0:
            return longest_matched_words + find_longest_matched_words(char_sequence[longest_word_length:])
        else:
            return longest_matched_words
    else:
        return find_longest_matched_words(char_sequence[1:])
    

def lex(df: DataFrame) -> DataFrame:
    """
    Calculate domain lexical features.
    Input: DF with domain_name column
    Output: DF with lexical features derived from domain_name added
    """
    df['lex_name_len'] = df['domain_name'].apply(len)
    df['lex_subdomain_count'] = df['domain_name'].apply(lambda x: x.count('.'))
    df['lex_subdomain_len'] = df['domain_name'].apply(lambda x: sum([len(y) for y in x.split('.')]))
    df['lex_digit_count'] = df['domain_name'].apply(lambda x: sum([1 for y in x if y.isdigit()]))
    df['lex_has_digit'] = df['domain_name'].apply(lambda x: 1 if sum([1 for y in x if y.isdigit()]) > 0 else 0)
    df['lex_phishing_keyword_count'] = df['domain_name'].apply(lambda x: sum(1 for w in phishing_keywords if w in x))

    # Save temporary domain name parts for lex feature calculation
    df['tmp_tld'] = df['domain_name'].apply(lambda x: tldextract.extract(x).suffix)
    df['tmp_sld'] = df['domain_name'].apply(lambda x: tldextract.extract(x).domain)
    df['tmp_stld'] = df['tmp_sld'] + "." + df['tmp_tld']
    df['tmp_concat_subdomains'] = df['domain_name'].apply(lambda x: remove_tld(x).replace(".",""))

    df['lex_tld_len'] = df['tmp_tld'].apply(len)                                                   # Length of TLD
    df['lex_tld_len'] = df['tmp_sld'].apply(len)                                                   # Length of SLD
    df['lex_sub_count'] = df['domain_name'].apply(lambda x: count_subdomains(x))                   # Number of subdomains
    df['lex_stld_unique_chars'] = df['tmp_stld'].apply(lambda x: len(set(x.replace(".", ""))))     # Number of unique characters in TLD and SLD
    df['lex_first_digit_flag'] = df['domain_name'].apply(lambda x: 1 if x[0].isdigit() else 0)     # Is first character a digit
    df['lex_www_flag'] = df['domain_name'].apply(lambda x: 1 if (x.split("."))[0] == "www" else 0) # Begins with www
    df['lex_sub_max_consonant_len'] = df['tmp_concat_subdomains'].apply(longest_consonant_seq)     # Max consonant sequence length
    df['lex_sub_norm_entropy'] = df['tmp_concat_subdomains'].apply(get_normalized_entropy)         # Normalized entropy od the domain name (without TLD)
    #df['lex_sub_digit_count'] = df['tmp_concat_subdomains'].apply(lambda x: (sum([1 for y in x if y.isdigit()])) if len(x) > 0 else None)
    #df['lex_sub_digit_ratio'] = df['lex_sub_digit_count'] / df['lex_name_len']                     # Digit ratio in subdomains
    df['lex_sub_consonant_ratio'] = df['tmp_concat_subdomains'].apply(lambda x: (sum(1 for c in x if c in 'bcdfghjklmnpqrstvwxyz') / len(x)) if len(x) > 0 else None)
    df['lex_sub_non_alphanum_ratio'] = df['tmp_concat_subdomains'].apply(lambda x: (sum(1 for c in x if not c.isalnum()) / len(x)) if len(x) > 0 else None)
    df['lex_sub_hex_ratio'] = df['tmp_concat_subdomains'].apply(lambda x: (sum(1 for c in x if c in '0123456789ABCDEFabcdef') / len(x)) if len(x) > 0 else None)

    # Drop temporary columns
    df = df.drop(['tmp_tld', 'tmp_sld', 'tmp_stld', 'tmp_concat_subdomains'], axis=1, inplace=False)

    return df