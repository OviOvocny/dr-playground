import click


@click.command()
def analyze():
    click.echo("Analysing...")
    # analyzer = NgramsAnalyzer('floor/phishing.parquet')
    # analyzer.analyze_ngrams(20)


@click.group()
def ngrams():
    """Loader subcommands."""
    pass


ngrams.add_command(analyze)
