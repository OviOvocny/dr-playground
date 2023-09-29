import click
import loader.loader as ldr
import loader.transformers as trans


@click.command()
@click.option('-c', '--cache-mode',
              type=click.Choice(['auto', 'force-refresh', 'force-local']), default='auto',
              help='Whether to use cached data or not. Defaults to auto, checking for changes in database.')
@click.option('-st', '--start-at',
              type=click.Choice(list(trans.get_transformations().keys())),
              default=None, multiple=False,
              help="Specifies that transformations should start from a specific checkpoint. "
                   "If the checkpoint is not stored for a dataset, the whole transformation chain will be run.")
@click.option('-cp', '--checkpoint',
              type=click.Choice(list(trans.get_transformations().keys())),
              default=None, multiple=True,
              help="Specifies that an intermediary checkpoint should be saved AFTER a certain transformation."
                   "Can be used multiple times.")
def run(cache_mode, start_at, checkpoint):
    ldr.run(cache_mode, start_at, checkpoint)


@click.command(help="Prints a list of all enabled transformations.")
def list_transformations():
    click.echo("Configured transformation chain:")
    click.echo(f"     {'Name'.ljust(14, ' ')} Saves checkpoint (by default)")
    i = 1
    for name, (save, _) in trans.get_transformations().items():
        click.echo(f"{i:02d}.  {name.ljust(14, ' ')} {'yes' if save else 'no'}")
        i += 1


@click.group()
def loader():
    """Loader subcommands."""
    pass


loader.add_command(run)
loader.add_command(list_transformations)
