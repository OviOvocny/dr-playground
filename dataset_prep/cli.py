import os.path
import sys
from typing import List, Optional, Callable

from pyarrow import Table
from pyarrow.parquet import read_table, write_table

import click

from . import set_operations, split_operations


def load_table(file: str) -> Table:
    if not os.path.isfile(file):
        click.echo(f"File not found: {file}")
        sys.exit(1)

    return read_table(file, use_threads=True)


def save_table(table: Table, file: str):
    if os.path.isfile(file):
        if not click.confirm(f"File {file} exists. Overwrite?", default=True):
            return

    write_table(table, file)


def get_out_name(files: List[str], command: str, out_name: Optional[str]):
    if out_name is not None:
        return out_name

    return "{0}_{1}.parquet".format(command, "_".join(os.path.splitext(os.path.basename(x))[0] for x in files))


def do_set_op(op: Callable[[Table, Table], Table], op_name: str, files: List[str], out: Optional[str]):
    click.echo(f"Making {op_name}")
    left = load_table(files[0])
    right = load_table(files[1])
    result = op(left, right)
    out_name = get_out_name(files, op_name, out)
    save_table(result, out_name)


@click.command(help="Creates an intersection of domain data in two parquets")
@click.argument('files', nargs=2, type=str, required=True)
@click.option('-o', '--out', type=str, required=False, help="Output file name")
def intersect(files: List[str], out: Optional[str]):
    do_set_op(set_operations.make_intersection, "intersection", files, out)


@click.command(help="Creates an union of domain data in two parquets")
@click.argument('files', nargs=2, type=str, required=True)
@click.option('-o', '--out', type=str, required=False, help="Output file name")
def union(files: List[str], out: Optional[str]):
    do_set_op(set_operations.make_intersection, "union", files, out)


@click.command(help="Creates a difference of domain data in two parquets (first \\ second)")
@click.argument('files', nargs=2, type=str, required=True)
@click.option('-o', '--out', type=str, required=False, help="Output file name")
def difference(files: List[str], out: Optional[str]):
    do_set_op(set_operations.make_intersection, "difference", files, out)


@click.command(help="Splits an input parquet into two random samples A, B")
@click.argument('split_ratio', nargs=1, type=float, required=True)
@click.argument('input_file', nargs=1, type=str, required=True)
@click.option('-oa', '--out-a', type=str, required=False, help="Output A file name")
@click.option('-ob', '--out-b', type=str, required=False, help="Output B file name")
@click.option('-s', '--presample', type=float, required=False, default=1.0,
              help="If specified, the input dataset will be randomly sampled before splitting")
@click.option('-r', '--random-seed', type=int, required=False, default=42, help="Output B file name")
def split(split_ratio: float, input_file: str, out_a: Optional[str], out_b: Optional[str], presample: Optional[float],
          random_seed: int = 42):
    click.echo(f"Splitting (A = {split_ratio}, B = {1 - split_ratio})")

    in_file_name = os.path.splitext(os.path.basename(input_file))[0]
    presample_name = f"_sample_{presample}_" if presample is not None and presample < 1.0 else "_"
    out_a = out_a or f"{in_file_name}{presample_name}split_{split_ratio}_A.parquet"
    out_b = out_b or f"{in_file_name}{presample_name}split_{split_ratio}_B.parquet"

    in_table = load_table(input_file)
    a, b = split_operations.make_split(in_table, a_frac=split_ratio, pre_sample=presample, random_state=random_seed)
    save_table(a, out_a)
    save_table(b, out_b)


@click.command()
def stratified_split():
    click.echo("Splitting using stratification...")


@click.group()
def prep():
    """Prep subcommands."""
    pass


prep.add_command(intersect)
prep.add_command(union)
prep.add_command(difference)
prep.add_command(split)
prep.add_command(stratified_split)
