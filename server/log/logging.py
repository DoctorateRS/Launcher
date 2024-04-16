import inspect
import logging
import os


def log(
    message: str,
    *,
    log_level: str = "INFO",
    stdout: bool = True,
    log_file: bool = True,
    name_override: str | None = None,
) -> None:
    """Log a message to the console and/or a log file.

    Arguments:
    ---------
        message (str):
            The message to be logged.
        log_level (str):
            The level at which to log the message. Must be one of "INFO", "DEBUG", "WARNING", "ERROR", "EXCEPTION", or "CRITICAL".
            Defaults to "INFO".
        stdout (bool):
            If True, log the message to the console.
            Defaults to True.
        log_file (bool):
            If True, log the message to the log file.
            Defaults to True.
        name_override (str | None):
            Override the name of the logger. If not provided, the name of the module calling this function will be used as the logger name.

    """
    caller_name = name_override if name_override else os.path.basename(inspect.stack()[-1].filename)
    if not logging.getLogger(caller_name).hasHandlers():
        log_file_logger = logging.getLogger(caller_name)
        log_file_handler = logging.FileHandler("ODPy.log", mode="a", encoding="utf-8")
        log_file_logger.setLevel(logging.INFO)
        log_file_logger.propagate = False
        log_file_formatter = logging.Formatter(fmt="%(name)-15s :: %(levelname)-8s :: %(message)s")
        log_file_handler.setFormatter(log_file_formatter)
        log_file_logger.addHandler(log_file_handler)
    else:
        log_file_logger = logging.getLogger(caller_name)
    if not logging.getLogger(f"stdout.{caller_name}").hasHandlers():
        stdout_logger = logging.getLogger(f"stdout.{caller_name}")
        stdout_handler = logging.StreamHandler()
        stdout_logger.setLevel(logging.INFO)
        stdout_logger.propagate = False
        stdout_formatter = logging.Formatter(fmt="%(message)s")
        stdout_handler.setFormatter(stdout_formatter)
        stdout_logger.addHandler(stdout_handler)
    else:
        stdout_logger = logging.getLogger(f"stdout.{caller_name}")

    if stdout:
        match log_level:
            case "INFO":
                stdout_logger.info(message)
            case "DEBUG":
                stdout_logger.debug(message)
            case "WARNING":
                stdout_logger.warning(message)
            case "ERROR":
                stdout_logger.error(message)
            case "EXCEPTION":
                stdout_logger.exception(message)
            case "CRITICAL":
                stdout_logger.critical(message)
    if log_file:
        match log_level:
            case "INFO":
                log_file_logger.info(message)
            case "DEBUG":
                log_file_logger.debug(message)
            case "WARNING":
                log_file_logger.warning(message)
            case "ERROR":
                log_file_logger.error(message)
            case "EXCEPTION":
                log_file_logger.exception(message)
            case "CRITICAL":
                log_file_logger.critical(message)


def clear_log(log_filename: str = "ODPy.log") -> None:
    """Clear the content of the log file specified by log_filename.

    Arguments:
    ---------
    log_filename (str):
        The path to the log file to be cleared.

    """
    open(log_filename, "w", encoding="utf-8").close()
