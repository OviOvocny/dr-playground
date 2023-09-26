import click

from loader.cli import loader
from dataset_prep.cli import prep
from ngrams.cli import ngrams


@click.group()
def main():
    """Main CLI for dr-toolkit."""
    pass


main.add_command(loader)
main.add_command(prep)
main.add_command(ngrams)

if __name__ == "__main__":
    main()
