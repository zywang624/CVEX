import logging

log_level = logging.INFO


def get_logger(name: str) -> logging.Logger:
    log = logging.getLogger(name)
    if log.hasHandlers():
        return log
    console_log_handler = logging.StreamHandler()
    console_log_handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - [%(name)s] %(message)s"))
    log.addHandler(console_log_handler)
    global log_level
    log.setLevel(log_level)
    return log