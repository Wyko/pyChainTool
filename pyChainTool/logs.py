"""Logic for logging functionality."""

import logging
import sys
from logging.handlers import TimedRotatingFileHandler
from pathlib import Path

# Create the output directory
APP_NAME = "pyChainTool"
OUTPUT_DIR = Path.home() / ("." + APP_NAME)
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


def setup_logging(console_level: int = logging.DEBUG) -> None:
    """Set up the logger to output to a file and to the console."""
    logger = get_root_logger()
    logger.setLevel(logging.DEBUG)

    # Send all logs (including DEBUG) to a log file
    fp_logs = OUTPUT_DIR / "logs.txt"
    file_handler = TimedRotatingFileHandler(filename=fp_logs.resolve(), when="D", backupCount=5)
    file_handler.setFormatter(logging.Formatter("%(asctime)s - %(name)s - %(levelname)s: %(message)s"))
    file_handler.setLevel(logging.DEBUG)
    logger.addHandler(file_handler)

    # Send INFO level and above logs to the console
    console_handler = logging.StreamHandler()
    console_handler.setLevel(level=console_level)
    console_handler.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
    logger.addHandler(console_handler)


def is_console_handler(handler: logging.Handler) -> bool:
    """Check if a logging handler is connected to the console.

    Args:
    ----
        handler (logging.Handler): The handler to check.

    Returns:
    -------
        bool: True if the handler is connected to the console.

    """
    return isinstance(handler, logging.StreamHandler) and handler.stream in {sys.stdout, sys.stderr}


def set_logger_level(level: int) -> None:
    """Set the level of the console logger to the specified level.

    Args:
    ----
        level (int): The level to set the logger to.

    """
    for handler in get_root_logger().handlers:
        if is_console_handler(handler):
            handler.setLevel(level)


def get_logger(child_name: str) -> logging.Logger:
    "Create a child logger to the application root logger."
    return get_root_logger().getChild(child_name)


def get_root_logger() -> logging.Logger:
    """Return the package's top-level logger.

    This is here to make a single place to document the naming of the logger, and so that we can inherit from it
    for loggers that need to be generated before the config module.
    """
    return logging.getLogger(APP_NAME)


setup_logging(console_level=logging.DEBUG)
