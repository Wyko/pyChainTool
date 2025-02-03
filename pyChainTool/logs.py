"""Logic for logging functionality."""

import logging
from logging.handlers import TimedRotatingFileHandler
from pathlib import Path

# Create the output directory
APP_NAME = "pyChainTool"
OUTPUT_DIR = Path.home() / ("." + APP_NAME)
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


def setup_logging(logger: logging.Logger, level: int = logging.DEBUG) -> None:
    """Set up the logger to output to a file and to the console."""

    logger.setLevel(logging.DEBUG)

    # Send all logs (including DEBUG) to a log file
    fp_logs = OUTPUT_DIR / "logs.txt"
    file_handler = TimedRotatingFileHandler(filename=fp_logs.resolve(), when="D", backupCount=5)
    file_handler.setFormatter(logging.Formatter("%(asctime)s - %(name)s - %(levelname)s: %(message)s"))
    file_handler.setLevel(logging.DEBUG)
    logger.addHandler(file_handler)

    # Send INFO level and above logs to the console
    console_handler = logging.StreamHandler()
    console_handler.setLevel(level=level)
    console_handler.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
    logger.addHandler(console_handler)

    logger.debug("Configured logging for " + logger.name)


root_logger = logging.getLogger(APP_NAME)

setup_logging(logger=root_logger, level=logging.DEBUG)
