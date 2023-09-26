import click


@click.command()
def intersect():
    click.echo("Intersecting...")


@click.command()
def union():
    click.echo("Making union...")


@click.command()
def difference():
    click.echo("Making difference...")


@click.command()
def split():
    click.echo("Splitting...")


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
