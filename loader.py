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

import sys, os
import pymongo, pymongo.errors
from pandas import DataFrame
import pyarrow as pa
import pyarrow.parquet as pq
from pymongoarrow.monkey import patch_all
patch_all()

from config import Config

client = pymongo.MongoClient(Config.MONGO_URI)
db = client[Config.MONGO_DB]

def save_df(df: DataFrame, name: str, prefix: str = ''):
    """
    Save a pandas dataframe to parquet in the floor directory. 
    If prefix is specified, save to a subdirectory.
    """
    table = pa.Table.from_pandas(df)
    prefix_path = f'floor/{prefix}' if prefix != '' else 'floor'
    # create prefix directory if it doesn't exist
    if not os.path.exists(prefix_path):
        os.makedirs(prefix_path)
    print(f'Saving to {prefix_path}/{name}.parquet', file=sys.stderr)
    pq.write_table(table, f'{prefix_path}/{name}.parquet')

from projection import pipeline
from schema import schema
def get_df(collection_name: str):
    """Wrapper for pymongoarrow.find/aggregate_whatever_all because it's typed NoReturn for some godforsaken reason."""
    if Config.CACHE and os.path.exists(f'cache/{collection_name}.parquet'):
        print(f'[{collection_name}] Loading from cache', file=sys.stderr)
        return pq.read_table(f'cache/{collection_name}.parquet').to_pandas()
    else:
        print(f'[{collection_name}] Running Mongo find operation', file=sys.stderr)
        for attempt in range(5):
            try:
                table = db[collection_name].aggregate_arrow_all(pipeline, schema=schema)
                pq.write_table(table, f'cache/{collection_name}.parquet') # no pylance, this IS reachable
                return table.to_pandas()
            except pymongo.errors.AutoReconnect:
                print(f'[{collection_name}] AutoReconnect, retrying', file=sys.stderr)
                continue
            return None


import transformers
def run():
    for label, collection_name in Config.COLLECTIONS.items():
        #==> run aggregation pipeline to get select fields from mongo
        df = get_df(collection_name)

        # if df failed to load, skip this collection
        if df is None:
            print(f'[{collection_name}] Failed to load data, skipping', file=sys.stderr)
            continue


        print(f'[{collection_name}] Processing {label} data', file=sys.stderr)
        #==> transform data
        # iterate over custom functions in transformers module and apply them to the dataframe
        for name, func in transformers.__dict__.items():
            if callable(func) and name.startswith('transform_'):
                clean_name = name.removeprefix("transform_").removesuffix("_save")
                print(f'[{collection_name}] Running {clean_name} transform', file=sys.stderr)
                df = func(df)
                if name.endswith('_save'):
                    save_df(df, label, prefix=f'after_{clean_name}')

        #==> drop nontraining fields
        # TODO: probably do this later before training, but save the fields here

        #==> write to parquet
        save_df(df, label)

if __name__ == '__main__':
    run()