import pyarrow as pa
from pyarrow import Table


def make_intersection(left: Table, right: Table) -> Table:
    result = left.join(right_table=right, keys='domain_name', join_type='inner', right_suffix='__right_',
                       coalesce_keys=True, use_threads=True)

    all_right_names = [f"{x}__right_" for x in right.column_names]
    all_right_names.remove("domain_name__right_")
    return result.drop_columns(all_right_names)


def make_union(left: Table, right: Table) -> Table:
    right_not_in_left = left.join(right_table=right, keys='domain_name', join_type='right anti', coalesce_keys=True,
                                  use_threads=True)

    return pa.concat_tables([left, right_not_in_left])


def make_difference(left: Table, right: Table) -> Table:
    result = left.join(right_table=right, keys='domain_name', join_type='left anti', coalesce_keys=True,
                       use_threads=True)
    return result
