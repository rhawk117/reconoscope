
import abc
import argparse
import asyncio
import dataclasses
from typing import Any, Generic, Self, TypeVar
from rich.console import Console


def cli_arg(
    name: str,
    *,
    required: bool = False,
    default=None,
    type: Any = str,
    help: str = "",
    action: str | None = None,
    **dataclass_kwargs,
) -> Any:
    metadata = {
        "help": help,
        "name": name,
        "required": required,
        "action": action,
    }
    if action not in ("store_true", "store_false"):
        metadata["type"] = type

    return dataclasses.field(default=default, **dataclass_kwargs, metadata=metadata)


class ArgparseModel:
    '''
    expects the `dataclass` decorator to be used
    along with the `cli_arg` function for field
    definitions.
    '''
    @classmethod
    def register(cls, parser: argparse.ArgumentParser) -> None:
        """
        register the arguments with argparse

        Parameters
        ----------
        parser : argparse.ArgumentParser
        """
        for field in dataclasses.fields(cls):  # type: ignore
            name = field.metadata["name"]
            default = field.default if field.default is not dataclasses.MISSING else None

            add_kwargs = {
                "default": default,
                "help": field.metadata.get("help", ""),
            }
            if field.metadata.get("required") is not None:
                add_kwargs["required"] = field.metadata["required"]

            if "type" in field.metadata:
                add_kwargs["type"] = field.metadata["type"]

            if field.metadata.get("action", None):
                add_kwargs["action"] = field.metadata["action"]

            parser.add_argument(name, **add_kwargs)

    def show(self) -> str:
        """
        Shows the CLI arguments

        Returns
        -------
        str
        """
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

    @classmethod
    def from_namespace(cls, args: argparse.Namespace) -> Self:
        """
        Create an instance of the model from argparse.Namespace

        Parameters
        ----------
        args : argparse.Namespace

        Returns
        -------
        ArgparseModel
        """

        field_names = {field.name for field in dataclasses.fields(cls)}  # type: ignore
        arg_dict = {k: v for k, v in vars(args).items() if k in field_names}
        return cls(**arg_dict)  # type: ignore-


A = TypeVar("A", bound=ArgparseModel)


class CLIGroup(abc.ABC, Generic[A]):
    model: type[A]
    console = Console()

    def __init__(self, parser: argparse.ArgumentParser) -> None:
        self.model.register(parser)

    @abc.abstractmethod
    async def routine(self, args: A) -> None: ...

    def __call__(self, args: argparse.Namespace) -> None:
        parsed_args: A = self.model.from_namespace(args)
        asyncio.run(self.routine(parsed_args))


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