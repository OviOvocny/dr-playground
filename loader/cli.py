import click
import loader.loader as ldr


@click.command()
@click.option('-c', '--cache-mode',
              type=click.Choice(['auto', 'force-refresh', 'force-local']), default='auto',
              help='Whether to use cached data or not. Defaults to auto, checking for changes in database.')
def run(cache_mode):
    ldr.run(cache_mode)


@click.group()
def loader():
    """Loader subcommands."""
    pass


loader.add_command(run)
