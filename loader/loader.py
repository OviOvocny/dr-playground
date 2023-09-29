# This is the script that loads the data from MongoDB 
# and creates parquet files with transformed data.
#
# See config.py for some configuration options. 
# See projection.py for the mongo aggregation pipeline
# See schema.py for the schema of the data
# See transformers/ for the transformers that are applied to the data
# and the README.md in there for more info about authoring transformers.
#
# This script is intended to be run from the command line or a notebook.
# In a notebook, import the run() function and call it to run the script.
# Resulting parquet files will be saved in the floor/ directory.
# If CACHE is enabled in config.py, the script will skip pulling
# data from mongo if it's already cached in the cache/ directory.
#
# Play with the parquet files in the floor/ directory in a jupyter notebook
# to get a feel for the data and how it's transformed.
#
# You shouldn't need to touch this script at all.

import os
import sys
from typing import Tuple, Optional

import click
import pyarrow as pa
import pyarrow.parquet as pq
import pymongo
import pymongo.errors
from pandas import DataFrame
from pyarrow import ArrowException
from pymongoarrow.monkey import patch_all
from config import Config
from .projection import query, projection
from .schema import schema
import loader.transformers

patch_all()

client = pymongo.MongoClient(Config.MONGO_URI)
db = client[Config.MONGO_DB]

_cache_path = os.path.join("data", "cache")
_floor_path = os.path.join("data", "floor")

if not os.path.exists(_cache_path):
    os.makedirs(_cache_path)
if not os.path.exists(_floor_path):
    os.makedirs(_floor_path)


def save_df(df: DataFrame, label: str, checkpoint_name: Optional[str] = None):
    """
    Save a pandas dataframe to parquet in the floor directory. 
    If prefix is specified, save to a subdirectory.
    """
    table = pa.Table.from_pandas(df)

    target_dir = _floor_path if checkpoint_name is None else os.path.join(_floor_path, f"after_{checkpoint_name}")
    if not os.path.exists(target_dir):
        os.makedirs(target_dir)

    print(f'[{label}] Saving to {target_dir}/{label}.parquet', file=sys.stderr)
    pq.write_table(table, os.path.join(target_dir, f"{label}.parquet"),
                   coerce_timestamps='ms', allow_truncated_timestamps=True)


def get_df(label: str, collection_name: str, cache_mode: str):
    """Wrapper for pymongoarrow.find/aggregate_whatever_all because it's typed NoReturn for some godforsaken reason."""
    # determine whether to refresh from mongo
    # TODO: implement auto cache check
    if cache_mode not in ['auto', 'force-refresh', 'force-local']:
        print(f'Invalid cache_mode "{cache_mode}", defaulting to auto!', file=sys.stderr)
        cache_mode = 'auto'

    will_refresh = False
    if cache_mode == 'auto':
        print('[NOTE] Auto cache check not yet implemented, defaulting to local data! Use '
              '"-c force-refresh" in CLI or pass "force-refresh" to cache_mode param to load from DB.',
              file=sys.stderr)
    elif cache_mode == 'force-refresh':
        will_refresh = True

    collection_cached_path = os.path.join(_cache_path, f"{collection_name}.parquet")

    # load from cache if it exists and we're not refreshing
    if not will_refresh and os.path.exists(collection_cached_path):
        print(f'[{label}] Loading from cache', file=sys.stderr)
        return pq.read_table(collection_cached_path).to_pandas(safe=False, self_destruct=True,
                                                               split_blocks=True)
    # otherwise, refresh from mongo
    else:
        if not will_refresh:
            print(f'[{label}] Cache miss, refreshing anyway...', file=sys.stderr)
        print(f'[{label}] Running Mongo operations on collection {collection_name}', file=sys.stderr)
        for attempt in range(5):
            try:
                table = db[collection_name].find_arrow_all(query, schema=schema, projection=projection)
                print(f"[{label}] Writing to parquet")
                pq.write_table(table, collection_cached_path,
                               coerce_timestamps='ms',
                               allow_truncated_timestamps=True)
                return table.to_pandas(safe=False, self_destruct=True, split_blocks=True)
            except pymongo.errors.AutoReconnect:
                print(f'[{label}] AutoReconnect, retrying for {(attempt + 1)} time', file=sys.stderr)
                continue


def get_df_checkpoint(label: str, checkpoint_name: str) -> DataFrame | None:
    path = os.path.join(_floor_path, f"after_{checkpoint_name}", f"{label}.parquet")
    if not os.path.isfile(path):
        return None

    try:
        return pq.read_table(path).to_pandas(safe=False, self_destruct=True, split_blocks=True)
    except ArrowException as e:
        print(f"Error reading 'after_{checkpoint_name}/{label}.parquet': {str(e)}", file=sys.stderr)
        return None


def run(cache_mode='auto', start_at: str = None, checkpoints: Tuple[str] = ()):
    if len(Config.COLLECTIONS) == 0:
        print("Nothing to be done (check enabled collections in config)", file=sys.stderr)
        return

    transformations = loader.transformers.get_transformations()

    for label, collection_name in Config.COLLECTIONS.items():
        df = None
        # if 'start_at' is used, transformations must be skipped until the 'start_at' one is reached
        start_at_found = False

        if start_at is not None:
            # load from the specified checkpoint
            df = get_df_checkpoint(label, start_at)

        if df is None:
            # run aggregation pipeline to get select fields from mongo
            df = get_df(label, collection_name, cache_mode)
            start_at_found = True

        # if df failed to load, skip this collection
        if df is None:
            print(f'[{label}] Failed to load data, skipping', file=sys.stderr)
            continue

        # Transform data
        print(f'[{label}] Processing {label} data (collection {collection_name})', file=sys.stderr)
        for name, (save, func) in transformations.items():
            if not start_at_found:
                if name == start_at:
                    start_at_found = True
                continue

            save = save or (name in checkpoints)
            print(f'[{label}] Running transformation {name}', file=sys.stderr)
            df = func(df)
            if save:
                save_df(df, label, name)

        # write to parquet
        save_df(df, label)
