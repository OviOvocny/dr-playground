from typing import Callable, Optional, Dict
import pyarrow as pa
import pyarrow.parquet as pq
from pandas import DataFrame, Series
from sklearn.model_selection import train_test_split
from transformers.drop_nontrain import drop_nontrain_df as drop_nontrain
from transformers.cast_timestamp import cast_timestamp
import os.path


def make_train_test(benign_parquet: str, malign_parquet: str,
                    transformation: Optional[Callable[[DataFrame], DataFrame]] = None,
                    test_size=0.3, random_state=42):
    x, y, b, m = make_train(benign_parquet, malign_parquet, transformation)

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
               transformation: Optional[Callable[[DataFrame], DataFrame]] = None):
    malign = pq.read_table(f"{malign_parquet}.parquet")
    benign = pq.read_table(f"{benign_parquet}.parquet")

    print(f"Loaded {malign_parquet} for malign ({len(malign)} entries), {benign_parquet} "
          f"for benign ({len(benign)} entries)")

    benign = benign.cast(malign.schema)
    data = pa.concat_tables([malign, benign])
    df = data.to_pandas()

    benign_label = str(benign["label"][0])
    malign_label = str(malign["label"][0])

    if transformation is not None:
        df = transformation(df)

    class_map = {benign_label: 0, malign_label: 1}
    labels = df['label'].apply(lambda x: class_map[x])
    df.drop(columns=['label'], inplace=True)

    return df, labels, benign_label, malign_label


def make_test(test_parquet: str, transformation: Optional[Callable[[DataFrame], DataFrame]] = None,
              class_map: Optional[Dict[str, int]] = None, is_benign=Optional[bool]):
    fn = f"{test_parquet}.parquet"

    if not os.path.isfile(fn):
        print("Testing data not found! Is the provided parquet name correct? Or maybe you want to use the split "
              "train/test data from training...")
        exit(1)

    data = pq.read_table(fn)
    print(f"Loaded {test_parquet} for test ({len(data)} entries)")
    df = data.to_pandas()

    if transformation is not None:
        df = transformation(df)

    if class_map is not None:
        labels = df['label'].apply(lambda x: class_map[x])
    elif is_benign is not None:
        labels = Series(0 if is_benign else 1, range(len(df)))
    else:
        raise ValueError("Either class_map or is_benign must be provided")

    df.drop(columns=['label'], inplace=True)
    return df, labels


def load_stored_test_data(test_parquet: str):
    fn = f"{test_parquet}.parquet"
    if not os.path.isfile(fn):
        print("Testing data not found! Has the model been trained using the split train/test method?")
        exit(1)

    data = pq.read_table(fn).to_pandas(safe=False, self_destruct=True, split_blocks=True)  # type: DataFrame
    y_test = data["_labels"]
    X_test = data.drop(columns=["_labels"])
    del data

    return X_test, y_test


def basic_preprocessor(df: DataFrame):
    return cast_timestamp(drop_nontrain(df))
