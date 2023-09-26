from math import floor
from typing import Tuple, List, Optional

import pandas as pd
from pandas import DataFrame, Series
from pyarrow import Table
from sklearn.model_selection import ShuffleSplit, train_test_split


def make_split(in_table: Table, a_frac: float = 0.7, pre_sample: float = 1.0,
               random_state: int = 42, n_splits: int = 10) -> Tuple[Table, Table]:
    """
    Splits an input PyArrow Table into two Tables (a, b). The ratio of items that will be placed in the table `a`
    is controlled by a_frac.

    :param in_table: The input Table.
    :param a_frac: The split ratio.
    :param pre_sample: If lower than 1.0, the input dataset will be randomly sampled before splitting.
    :param random_state: Seed for RNG.
    :param n_splits: Number of re-shuffling & splitting iterations.
    :return: A tuple with two Table objects with the split dataset.
    """
    df = in_table.to_pandas(split_blocks=True)  # type: DataFrame
    if pre_sample < 1.0:
        df = df.sample(frac=pre_sample, ignore_index=True, random_state=random_state)

    a_samples = floor(len(df) * a_frac)
    b_samples = len(df) - a_samples
    cv = ShuffleSplit(n_splits=n_splits, train_size=a_samples, test_size=b_samples,
                      random_state=random_state)
    x, y = next(cv.split(X=df, y=None))
    x, y = df.loc[x], df.loc[y]
    return Table.from_pandas(x), Table.from_pandas(y)


def make_stratified_split(in_tables: List[Table], a_frac: float = 0.7, pre_sample: float | List[float] = 1.0,
                          random_state: int = 42, stratify_by_column: Optional[str] = None,
                          stratify_classmap: Optional[dict] = None):
    """
    Merges a list of PyArrow Tables and performs a stratified split. The ratio of items that will be placed in the
    first output set is controlled by a_frac. Returns a tuple of (A, y, B, z) where A, B are the two resulting datasets
    represented by a DataFrame and y, z are Series of labels.

    :param in_tables: The list of input Tables.
    :param a_frac: The split ratio.
    :param pre_sample: If this is a single float lower than 1.0, each input dataset will be randomly sampled before
    splitting. If it is a list of floats, each of the input Tables is sampled by its corresponding value from the list.
    :param random_state: Seed for RNG.
    :param stratify_by_column: If not None, stratification will be done based on the specified column. Otherwise, each
    input table will be considered a single class; the y, z output Series will contain the index of source table for
    each record.
    :param stratify_classmap: If stratify_by_column is used and this is not None, the stratification labels will be
    first mapped using this map.
    :return: A tuple in a shape of (DataFrame, Series, DataFrame, Series).
    """
    dfs = []
    lens = []
    i = 0
    for table in in_tables:
        df = table.to_pandas(split_blocks=True)  # type: DataFrame
        if isinstance(pre_sample, float) and pre_sample < 1.0:
            df = df.sample(frac=pre_sample)
        elif isinstance(pre_sample, list) and len(pre_sample) > i and pre_sample[i] < 1.0:
            df = df.sample(frac=pre_sample[i])
        dfs.append(df)
        lens.append((i, len(df)))
        i += 1

    df = pd.concat(dfs, ignore_index=True, sort=False, copy=False)
    if stratify_by_column is not None:
        if stratify_classmap is not None:
            y = df["label"].apply(lambda x: stratify_classmap[x])
        else:
            y = df["label"]
        df.drop(columns=["label"], inplace=True)
    else:
        y = pd.concat([Series(i, range(i_len)) for i, i_len in lens])

    x_a, x_b, y_a, y_b = train_test_split(df, y, train_size=a_frac, random_state=random_state,
                                          shuffle=True, stratify=y)

    return x_a, y_a, x_b, y_b
