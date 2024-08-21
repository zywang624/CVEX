import logging

LOG_LEVEL = logging.INFO


def get_logger(name: str) -> logging.Logger:
    global LOG_LEVEL
    log = logging.getLogger(name)
    if log.hasHandlers():
        return log
    console_log_handler = logging.StreamHandler()
    console_log_handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - [%(name)s] %(message)s"))
    log.addHandler(console_log_handler)
    log.setLevel(LOG_LEVEL)
    return log


def set_log_level(log_level: int):
    global LOG_LEVEL
    LOG_LEVEL = log_level
