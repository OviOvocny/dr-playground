from typing import Callable, Optional, Dict, List, Literal

import pandas
import pyarrow as pa
import pyarrow.parquet as pq
from pandas import DataFrame, Series
from pyarrow import Table
from sklearn.model_selection import train_test_split
from transformers.drop_nontrain import drop_nontrain_table as drop_nontrain
from transformers.cast_timestamp import cast_timestamp
import os.path


def make_train_test(benign_parquet: str, malign_parquet: str,
                    transformation_table: Optional[Callable[[Table], Table]] = None,
                    transformation_df: Optional[Callable[[DataFrame], DataFrame]] = None,
                    test_size=0.3, benign_sample: float = 1.0, malign_sample: float = 1.0, random_state=42):
    x, y, b, m = make_train(benign_parquet, malign_parquet, transformation_df, transformation_table,
                            benign_sample, malign_sample, random_state)

    x_train, x_test, y_train, y_test = train_test_split(
        x, y,
        test_size=test_size,
        random_state=random_state,
        shuffle=True,
        stratify=y
    )

    print(f"Created random train/test split. Training set: {len(x_train)} entries; Testing set: {len(x_test)} entries.")
    return x, y, x_train, x_test, y_train, y_test, b, m


def make_train(benign_parquet: str, malign_parquet: str,
               transformation_table: Optional[Callable[[Table], Table]] = None,
               transformation_df: Optional[Callable[[DataFrame], DataFrame]] = None,
               benign_sample: float = 1.0, malign_sample: float = 1.0, random_state: Optional[int] = 42):
    malign = pq.read_table(f"{malign_parquet}.parquet")
    benign = pq.read_table(f"{benign_parquet}.parquet")

    if transformation_table is not None:
        benign = transformation_table(benign)
        malign = transformation_table(malign)

    print(f"Loaded {malign_parquet} for malign ({len(malign)} entries), {benign_parquet} "
          f"for benign ({len(benign)} entries)")

    benign = benign.cast(malign.schema)

    benign_df = benign.to_pandas(split_blocks=True)  # type: DataFrame
    malign_df = malign.to_pandas(split_blocks=True)  # type: DataFrame

    if benign_sample < 1.0:
        benign_df = benign_df.sample(frac=benign_sample, random_state=random_state)
    if malign_sample < 1.0:
        malign_df = malign_df.sample(frac=malign_sample, random_state=random_state)

    df = pandas.concat([benign_df, malign_df], copy=False)

    benign_label = str(benign["label"][0])
    malign_label = str(malign["label"][0])

    if transformation_df is not None:
        df = transformation_df(df)

    class_map = {benign_label: 0, malign_label: 1}
    labels = df['label'].apply(lambda x: class_map[x])
    df.drop(columns=['label'], inplace=True)

    del benign_df
    del malign_df
    del benign
    del malign

    return df, labels, benign_label, malign_label


def make_test(test_parquets: str | List[str],
              class_map: Dict[str, int] | List[Literal[0, 1]] | Literal[0, 1],
              sample: float = 1.0,
              transformation_table: Optional[Callable[[Table], Table]] = None,
              transformation_df: Optional[Callable[[DataFrame], DataFrame]] = None):
    """
    Loads a single parquet or multiple parquets as testing data. Returns a tuple of (data, labels) where
    label 0 identifies benign records, label 1 identifies malign records.

    :param test_parquets: A path of the parquet or a list of paths. The ".parquet" extension must be omitted.
    :param class_map: Either a dictionary that maps a label (as found in the dataset) to 0 or 1; or a list of
                      0/1s where each item corresponds to a label of all record in one parquet in the test_parquets
                      list. If test_parquets is a single string, this may also be a single 0/1 literal.
    :param sample: If lower than 1.0, the resulting dataset will be randomly sampled, keeping a fraction of results
                   corresponding to this argument.
    :param transformation_table: A function that takes an arrow Table and returns a Table; called on each dataset before
                                 merging and converting to dataframe.
    :param transformation_df: A function that takes a dataframe and returns a dataframe; called on the merged dataset
                              before labelling. If class_map is a list, this must not drop any rows.
    """
    if isinstance(test_parquets, str):
        test_parquets = [test_parquets]
        if isinstance(class_map, int):
            class_map = [class_map]

    if isinstance(class_map, list) and len(test_parquets) != len(class_map):
        raise ValueError("class list length must be the same as the number of input parquets")

    tables = []
    table_lens = []
    first_table = None
    for parquet in test_parquets:
        fn = f"{parquet}.parquet"

        if not os.path.isfile(fn):
            print("Testing data not found! Is the provided parquet name correct? Or maybe you want to use the split "
                  "train/test data from training...")
            exit(1)

        data = pq.read_table(fn)
        if transformation_table is not None:
            data = transformation_table(data)

        print(f"Loaded {parquet} for test ({len(data)} entries)")
        if first_table is None:
            first_table = data
        else:
            data = data.cast(first_table.schema)
        tables.append(data)
        table_lens.append(len(data))

    df = pa.concat_tables(tables=tables).to_pandas(split_blocks=True)

    if transformation_df is not None:
        df = transformation_df(df)

    if isinstance(class_map, dict):
        labels = df['label'].apply(lambda x: class_map[x])
    elif isinstance(class_map, list):
        label_series = []
        for i in range(len(table_lens)):
            label_series.append(Series(class_map[i], range(table_lens[i])))
        labels = pandas.concat(label_series)
    else:
        raise Exception("class_map must be either a mapping dictionary or a list specifying the class for each "
                        "parquet in test_parquets")

    df.drop(columns=['label'], inplace=True)

    if sample < 1.0:
        df["_label"] = labels
        df = df.sample(frac=sample)
        labels = Series(df["_label"], copy=True)
        df.drop(columns=["_label"], inplace=True)

    return df, labels


def load_stored_test_data(test_parquet: str):
    fn = f"{test_parquet}.parquet"
    if not os.path.isfile(fn):
        print("Testing data not found! Has the model been trained using the split train/test method?")
        exit(1)

    data = pq.read_table(fn).to_pandas(safe=False, self_destruct=True, split_blocks=True)  # type: DataFrame
    y_test = Series(data["_labels"], copy=True)
    data.drop(columns=["_labels"], inplace=True)

    return data, y_test


def basic_preprocessor_table(table: Table):
    return drop_nontrain(table)


def basic_preprocessor_df(df: DataFrame):
    return cast_timestamp(df)
