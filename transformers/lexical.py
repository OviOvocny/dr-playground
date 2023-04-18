from pandas import DataFrame

def lex(df: DataFrame) -> DataFrame:
    """
    Calculate length of domain name.
    Input: DF with domain_name column
    Output: DF with name_length column added
    """
    df['name_length'] = df['domain_name'].apply(len)
    df['subdomain_count'] = df['domain_name'].apply(lambda x: x.count('.'))
    df['subdomain_length'] = df['domain_name'].apply(lambda x: sum([len(y) for y in x.split('.')]))
    df['digit_count'] = df['domain_name'].apply(lambda x: sum([1 for y in x if y.isdigit()]))
    df['has_digit'] = df['domain_name'].apply(lambda x: 1 if sum([1 for y in x if y.isdigit()]) > 0 else 0)
    return df