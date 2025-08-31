
import abc
import argparse
import dataclasses
from typing import TypeVar

class Renderable(abc.ABC):
    @abc.abstractmethod
    def console_output(self) -> str:
        pass

def cli_arg(
    name: str,
    *,
    default=None,
    help: str = "",
) :
    return dataclasses.field(
        default=default,
        metadata={
            "help": help,
            "name": name,
        },
    )


class ArgumentModel:
    '''
    expects the `dataclass` decorator to be used
    along with the `cli_arg` function for field
    definitions.
    '''
    @classmethod
    def register(cls, parser: argparse.ArgumentParser) -> None:
        for field in dataclasses.fields(cls): # type: ignore
            name = field.metadata['name']
            help = field.metadata.get("help", "")
            default = field.default if field.default is not dataclasses.MISSING else None
            parser.add_argument(name, default=default, help=help)

    def show(self) -> str:
        output = "CLI Arguments:\n"
        for field in dataclasses.fields(self): # type: ignore
            value = getattr(self, field.name)
            if value is not None:
                output += f" - [bold]{field.name}[/bold]: {value}\n"
        return output

    def has_options(self) -> bool:
        for field in dataclasses.fields(self): # type: ignore
            if getattr(self, field.name) is not None:
                return True
        return False

A = TypeVar('A', bound=ArgumentModel)

def get_argparse_arguments(
    parser: argparse.ArgumentParser,
    model: type[A]
) -> A:
    '''
    collect and parse arguments

    Parameters
    ----------
    parser : argparse.ArgumentParser
    model : type[A]

    Returns
    -------
    A
        _the type of model passed_

    Raises
    ------
    SystemExit
        _could not parse args_
    SystemExit
        _no args provided_
    '''
    model.register(parser)
    args = parser.parse_args()
    try:
        args = model(**vars(args))
    except TypeError as e:
        parser.error(f"Argument parsing error: {e}")
        parser.print_help()
        raise SystemExit(1) from e

    if not args.has_options():
        parser.print_help()
        raise SystemExit(0)

    return args