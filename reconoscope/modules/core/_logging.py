


import logging
import sys
from typing import TYPE_CHECKING

from loguru import logger
from rich.traceback import install as rich_tb_install

if TYPE_CHECKING:
    pass

_LOG_FORMAT = (
    '<green>{time:YYYY-MM-DD HH:mm:ss}</green> | '
    '<level>{level: <8}</level> | '
    '<cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - '
    '<level>{message}</level>'
)

_NOISEY_LOGGERS = (
    'httpx',
    'httpcore',
    'asyncio',
    'urllib3',
)

class _InterceptHandler(logging.Handler):
    """
    Ensures stdlib logging goes through loguru,
    makes it very simple and easy to log using the
    convience of stdlib while getting the benefits of loguru.
    """

    def emit(self, record: logging.LogRecord) -> None:
        try:
            level = logger.level(record.levelname).name
        except ValueError:
            level = record.levelno

        frame, depth = logging.currentframe(), 2
        while frame and frame.f_code.co_filename == logging.__file__:
            frame = frame.f_back  # type: ignore[assignment]
            depth += 1

        logger.opt(depth=depth, exception=record.exc_info).log(
            level, record.getMessage()
        )



def configure_lib_logger(
    *,
    level_name: str = "INFO",
    rich_tracebacks: bool = False,
) -> None:
    '''
    Configures the root logger of reconoscope
    when run interactively or via the CLI. These
    logs are pretty for users so they can debug
    or see what is happening.

    Parameters
    ----------
    level_name : str, optional
        by default "INFO"
    rich_tracebacks : bool, optional
        by default False
    '''
    root_logger = logging.getLogger()
    root_logger.handlers = [_InterceptHandler()]
    root_logger.setLevel(level_name)

    noisey_loggers =_NOISEY_LOGGERS
    for handle in noisey_loggers:
        logging.getLogger(handle).handlers = [_InterceptHandler()]
        logging.getLogger(handle).setLevel(level_name)

    logger.remove()
    logger.add(
        sys.stdout,
        format=_LOG_FORMAT,
        level=level_name,
        colorize=True,
        enqueue=True,
        backtrace=False,
        diagnose=False,
        catch=True,
    )
    if rich_tracebacks:
        rich_tb_install(show_locals=True, word_wrap=True)

    logger.debug('reconoscope native logger configured.')

def disable_lib_logger() -> None:
    '''
    Turns off the reconoscope logger
    for when it is used as a library.
    '''
    logger.remove()
    logging.getLogger().handlers = []
    for handle in _NOISEY_LOGGERS:
        logging.getLogger(handle).handlers = []