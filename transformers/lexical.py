from pandas import DataFrame

def name_length(df: DataFrame) -> DataFrame:
    """
    Calculate length of domain name.
    Input: DF with domain_name column
    Output: DF with name_length column added
    """
    df['name_length'] = df['domain_name'].apply(len)
    return df