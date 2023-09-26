from pyarrow import Table

from dataset_prep import set_operations, split_operations
from pyarrow.parquet import read_table, write_table
from loader.transformers.drop_nontrain import drop_nontrain_table as dnt

# ==== Set operations ====

l = read_table("data/floor/malware.parquet")
r = read_table("data/floor/cesnet2.parquet")

# drop non-training fields (excl. domain_name)
l = dnt(l)
r = dnt(r)

l = l.cast(r.schema)
res = l

# Union
# res = set_operations.make_union(l, r)

# Intersection
# res = set_operations.make_intersection(l, r)

# Difference
# res = set_operations.make_difference(l, r)

res = res.drop(["domain_name"])
write_table(res, "data/floor/result.parquet")

# ==== Split operations ====

in_p = read_table("data/floor/cesnet2.parquet")

# Basic split
# first param is ratio of items ending up in result A
# second param is pre-sampling of the input set (random sampling before splitting)
res_a, res_b = split_operations.make_split(in_p, 0.7, 1.0)

res_a = res_a.drop(["domain_name"])
res_b = res_b.drop(["domain_name"])
write_table(res_a, "data/floor/result_a.parquet")
write_table(res_b, "data/floor/result_b.parquet")

# Stratified train/test split of N input parquets

in_parquets = [
    #read_table("data/floor/cesnet2.parquet"),
    read_table("data/floor/benign.parquet"),
    read_table("data/floor/malware.parquet"),
    #read_table("data/floor/phishing.parquet"),
    # ...
]

# in this variant, the records will be "labeled" and stratified by the INPUT FILE (index) they come from
# - keeping the ratio of records between the input datasets
# A, y, B, z = split_operations.make_stratified_split(
#     in_parquets, 0.7, 1.0,
#     stratify_by_column=None,
#     stratify_classmap=None)

# in this variant, they will be stratified by the "label" column mapped to two classes
A, y, B, z = split_operations.make_stratified_split(
    in_parquets, 0.7, 1.0,
    stratify_by_column="label",
    stratify_classmap={
        "cesnet2:unknown": 0,
        "benign_2307:unknown": 0,
        "malware:unknown": 1,
        "misp_2307:phishing": 1
    })

A.drop(columns=["domain_name"], inplace=True)
B.drop(columns=["domain_name"], inplace=True)
A["label"] = y
B["label"] = z
write_table(Table.from_pandas(A), "data/floor/result_a.parquet")
write_table(Table.from_pandas(B), "data/floor/result_b.parquet")
