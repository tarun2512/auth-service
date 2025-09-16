import logging
import os
from logging import StreamHandler
from logging.handlers import RotatingFileHandler, SocketHandler

import yaml

from scripts.constants.env_config import Service


# this method is to read the configuration from backup.conf
def read_configuration(file_name):
    """
    :param file_name:
    :return: all the configuration constants
    """
    with open(file_name) as stream:
        try:
            return yaml.safe_load(stream)
        except Exception as e:
            print(f"Failed to load Configuration. Error: {e}")


config = read_configuration("scripts/logging/logger_conf.yml")

logging_config = config["logger"]


def get_logger():
    """
    Creates a rotating log
    """
    __logger__ = logging.getLogger("ilens")
    __logger__.setLevel(logging_config["level"].upper())
    log_formatter = "%(asctime)s - %(levelname)-6s - [%(threadName)5s:%(funcName)5s():" + "%(lineno)s] - %(message)s"
    time_format = "%Y-%m-%d %H:%M:%S"
    formatter = logging.Formatter(log_formatter, time_format)

    for each_handler in logging_config["handlers"]:
        if each_handler["type"] in ["RotatingFileHandler"] and Service.ENABLE_FILE_LOG:
            log_file = os.path.join(each_handler["file_path"] + logging_config["name"] + ".log")
            if not os.path.exists(each_handler["file_path"]):
                os.makedirs(each_handler["file_path"])
            temp_handler = RotatingFileHandler(
                log_file, maxBytes=each_handler["max_bytes"], backupCount=each_handler["back_up_count"]
            )
            temp_handler.setFormatter(formatter)
        elif each_handler["type"] in ["SocketHandler"]:
            temp_handler = SocketHandler(each_handler["host"], each_handler["port"])
        elif each_handler["type"] in ["StreamHandler"] and Service.ENABLE_CONSOLE_LOG:
            temp_handler = StreamHandler()
            temp_handler.setFormatter(formatter)

        else:
            temp_handler = None
        if temp_handler:
            __logger__.addHandler(temp_handler)

    return __logger__


logger = get_logger()
