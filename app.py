if __name__ == "__main__":
    from dotenv import load_dotenv

    load_dotenv()

import argparse
import gc

import uvicorn

from scripts.constants.env_config import Service
from scripts.logging.logging import logger

gc.collect()

ap = argparse.ArgumentParser()

if __name__ == "__main__":
    ap.add_argument(
        "--port",
        "-p",
        required=False,
        default=Service.PORT,
        help="Port to start the application.",
    )
    ap.add_argument(
        "--bind",
        "-b",
        required=False,
        default=Service.HOST,
        help="IP to start the application.",
    )
    arguments = vars(ap.parse_args())

    logger.info(f"App Starting at {arguments['bind']}:{arguments['port']}")
    uvicorn.run("main:app", host=arguments["bind"], port=int(arguments["port"]))
