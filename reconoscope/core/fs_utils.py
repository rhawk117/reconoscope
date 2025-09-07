"""
utility file system operations
"""

from __future__ import annotations

import pathlib

project_root = pathlib.Path(__file__).parent.parent.parent.resolve()


def join_root(*paths: str) -> pathlib.Path:
    """
    Join paths to the project root.

    Parameters
    ----------
    *paths : str
        _The paths to join_

    Returns
    -------
    str
        _The joined path_
    """
    return project_root.joinpath(*paths)



class FileConstraintsError(Exception): ...



def _validate_file_path(
    *,
    path: pathlib.Path,
    must_exist: bool = True,
    is_file: bool = True,
) -> FileConstraintsError | None:
    if must_exist and not path.exists():
        return FileConstraintsError(f'File not found: {path}')

    if is_file and not path.is_file():
        return FileConstraintsError(
            f'Expected a file but got a directory: {path}'
        )

    return None



def normalize_pathname(path: str, *, join_to_root: bool = False) -> pathlib.Path:
    '''
    Normalize a pathname, optionally joining it to the project root.

    Parameters
    ----------
    path : str
    join_to_root : bool, optional
        by default False

    Returns
    -------
    pathlib.Path
    '''
    if join_to_root:
        norm_path = join_root(path)
    else:
        norm_path = pathlib.Path(path).expanduser().resolve()

    return norm_path

def read_text(pathname: str, *, join_to_root: bool = False, encoding: str = 'utf-8') -> str:
    '''
    Read text from a file.

    Parameters
    ----------
    pathname : str
    join_to_root : bool, optional
        _Whether to make the path relative to the root_, by default False
    encoding : str, optional
         by default 'utf-8'

    Returns
    -------
    str

    Raises
    ------
    err
        _Invalid file name or file does not exist_
    '''
    norm_path = normalize_pathname(pathname, join_to_root=join_to_root)
    if err := _validate_file_path(path=norm_path):
        raise err

    return norm_path.read_text(encoding=encoding)

def write_text(
    *,
    pathname: str,
    content: str,
    join_to_root: bool = False,
    encoding: str = 'utf-8',
    append_mode: bool = False,
) -> None:
    '''
    Write text to a file, creating parent directories if needed.

    Parameters
    ----------
    pathname : str
    content : str
    join_to_root : bool, optional
        _Whether to assume it's relative to the project root_, by default False
    encoding : str, optional
        by default 'utf-8'
    append_mode : bool, optional
         by default False

    Raises
    ------
    err
        _Invalid file name_
    '''
    norm_path = normalize_pathname(pathname, join_to_root=join_to_root)
    if not norm_path.parent.exists():
        norm_path.parent.mkdir(parents=True, exist_ok=True)


    if err := _validate_file_path(
        path=norm_path,
        is_file=True
    ):
        raise err

    mode = 'a' if append_mode else 'w'
    with norm_path.open(mode, encoding=encoding) as f:
        f.write(content)