from typing import Optional
from pandas import DataFrame

import numpy as np

import math
import tldextract
from ._helpers import get_normalized_entropy

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
    consonant_count = sum(1 for char in domain if char in consonants)
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


def count_subdomains(domain: str) -> int:
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


def verify_tld(domain_suffix: str, known_tlds: set) -> int:
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
    ext = tldextract.extract(domain)
    subdomain = ext.subdomain
    sld = ext.domain
    result = subdomain + "." + sld if subdomain else sld
    return result


def vowel_count(domain: str) -> int:
    """Function returns the number of vowels in
    the domain name
    Args:
        domain (str): The domain name
    Returns:
        int: Number of vowels
    """
    vowels = set("aeiouy")
    return sum(1 for char in domain.lower() if char in vowels)


def extract_subdomains(domain: str) -> list:
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


def total_underscores_and_hyphens(domain: str) -> int:
    """Function returns the total number of underscores
    and hyphens in the domain name.

    Args:
        domain (str): The domain name

    Returns:
        int: Number of underscores and hyphens
    """
    return sum(domain.count(char) for char in ['_', '-'])


def consecutive_chars(domain: str) -> int:
    """Function returns the number of consecutive
    characters.

    Args:
        domain (str): The domain name

    Returns:
        int: Number of consecutive characters
    """
    if len(domain) == 0:
        return 0

    max_count = 1
    count = 1
    prev_char = domain[0]
    for char in domain[1:]:
        if char == prev_char:
            count += 1
            max_count = max(max_count, count)
        else:
            count = 1
        prev_char = char
    return max_count


def lex(df: DataFrame) -> DataFrame:
    """
    Calculate domain lexical features.
    Input: DF with domain_name column
    Output: DF with lexical features derived from domain_name added
    """
    df['lex_name_len'] = df['domain_name'].apply(len)
    # NOTUSED# df['lex_dots_count'] = df['domain_name'].apply(lambda x: x.count('.'))   # (with www and TLD) :-> lex_sub_count used instead
    # NOTUSED# df['lex_subdomain_len'] = df['domain_name'].apply(lambda x: sum([len(y) for y in x.split('.')]))  # without dots
    df['lex_digit_count'] = df['domain_name'].apply(lambda x: sum([1 for y in x if y.isdigit()]))
    df['lex_has_digit'] = df['domain_name'].apply(lambda x: 1 if sum([1 for y in x if y.isdigit()]) > 0 else 0)
    df['lex_phishing_keyword_count'] = df['domain_name'].apply(lambda x: sum(1 for w in phishing_keywords if w in x))
    df['lex_vowel_count'] = df['domain_name'].apply(lambda x: vowel_count(x))
    df['lex_underscore_hyphen_count'] = df['domain_name'].apply(lambda x: total_underscores_and_hyphens(x))
    df['lex_consecutive_chars'] = df['domain_name'].apply(lambda x: consecutive_chars(x))
    # NOTUSED# df['lex_norm_entropy'] = df['domain_name'].apply(get_normalized_entropy)              # Normalized entropy od the domain name

    # Save temporary domain name parts for lex feature calculation
    df['tmp_tld'] = df['domain_name'].apply(lambda x: tldextract.extract(x).suffix)
    df['tmp_sld'] = df['domain_name'].apply(lambda x: tldextract.extract(x).domain)
    df['tmp_stld'] = df['tmp_sld'] + "." + df['tmp_tld']
    df['tmp_concat_subdomains'] = df['domain_name'].apply(lambda x: remove_tld(x).replace(".", ""))

    df['lex_tld_len'] = df['tmp_tld'].apply(len)  # Length of TLD
    df['lex_sld_len'] = df['tmp_sld'].apply(len)  # Length of SLD
    df['lex_sub_count'] = df['domain_name'].apply(lambda x: count_subdomains(x))  # Number of subdomains (without www)
    df['lex_stld_unique_char_count'] = df['tmp_stld'].apply(
        lambda x: len(set(x.replace(".", ""))))  # Number of unique characters in TLD and SLD
    df['lex_begins_with_digit'] = df['domain_name'].apply(
        lambda x: 1 if x[0].isdigit() else 0)  # Is first character a digit
    df['lex_www_flag'] = df['domain_name'].apply(lambda x: 1 if (x.split("."))[0] == "www" else 0)  # Begins with www
    df['lex_sub_max_consonant_len'] = df['tmp_concat_subdomains'].apply(
        longest_consonant_seq)  # Max consonant sequence length
    df['lex_sub_norm_entropy'] = df['tmp_concat_subdomains'].apply(
        get_normalized_entropy)  # Normalized entropy od the domain name (without TLD)
    df['lex_sub_digit_count'] = df['tmp_concat_subdomains'].apply(
        lambda x: (sum([1 for y in x if y.isdigit()])) if len(x) > 0 else 0).astype("float")
    df['lex_sub_digit_ratio'] = df['lex_sub_digit_count'] / df['lex_name_len']  # Digit ratio in subdomains
    df['lex_sub_consonant_ratio'] = df['tmp_concat_subdomains'].apply(
        lambda x: (sum(1 for c in x if c in 'bcdfghjklmnpqrstvwxyz') / len(x)) if len(x) > 0 else 0)
    df['lex_sub_non_alphanum_ratio'] = df['tmp_concat_subdomains'].apply(
        lambda x: (sum(1 for c in x if not c.isalnum()) / len(x)) if len(x) > 0 else 0)
    df['lex_sub_hex_ratio'] = df['tmp_concat_subdomains'].apply(
        lambda x: (sum(1 for c in x if c in '0123456789ABCDEFabcdef') / len(x)) if len(x) > 0 else 0)

    # Drop temporary columns
    df = df.drop(['tmp_tld', 'tmp_sld', 'tmp_stld', 'tmp_concat_subdomains'], axis=1, inplace=False)

    return df
