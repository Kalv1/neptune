"""main module"""
import threading

import api
from models import create_db
from tasks import tasks_thread
from utils import APIServer, Logger
from uvicorn import Config

logger = Logger("main")

if __name__ == "__main__":
    logger.info('starting Neptune !')
    create_db()
    threading.Thread(target=tasks_thread).start()
    server_config = Config(api.neptune_api, host="0.0.0.0", port=5000)
    server = APIServer(server_config)
    server.run()
