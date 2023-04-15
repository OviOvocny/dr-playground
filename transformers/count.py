from pandas import DataFrame

def countries_count(df: DataFrame) -> DataFrame:
    """
    Calculate number of countries for each domain.
    Input: DF with countries column
    Output: DF with countries_count column added
    """
    df['countries_count'] = df['countries'].apply(lambda countries: len(list(set(countries))) if countries is not None else 0)
    return df

def dns_count(df: DataFrame) -> DataFrame:
    """
    Calculate number of DNS records for each domain.
    Input: DF with dns_* columns
    Output: DF with dns_*_count columns added
    """
    for column in df.columns:
        if column.startswith('dns_'):
            df[column + '_count'] = df[column].apply(lambda values: len(values) if values is not None else 0)
    return df