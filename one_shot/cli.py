import json
from typing import List
from .feature_extract import resolve, extract
import click

import pprint
pp = pprint.PrettyPrinter(indent=2, depth=4)


@click.command(help="Resolves one or more domains")
@click.argument('domains', nargs=-1, type=str, required=True)
def resolve(domains: List[str]):
    result = {}
    for domain in domains:
        result[domain] = resolve(domain)

    return print(result)


@click.command(help="Resolves and transforms one or more domains")
@click.argument('domains', nargs=-1, type=str, required=True)
@click.option('-d', '--drop-nontrain', type=bool, is_flag=True, default=False, required=False,
              help='Drop non-training fields')
def extract_features(domains: List[str], drop_nontrain: bool):
    result = {}
    for domain in domains:
        result[domain] = extract(domain, drop_nontrain)

    pp.pprint(result)


@click.group()
def one_shot():
    pass


one_shot.add_command(resolve)
one_shot.add_command(extract_features)
