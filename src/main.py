import asyncio
import logging
import signal
import sys
sys.stdout.reconfigure(line_buffering=True)
from src.config import Settings
from src.storage import StorageEngine
from src.heuristics import HeuristicsEngine
from src.gemini_client import GeminiClassifier
from src.dispatcher import Dispatcher
from src.ingestion import IngestionWorker

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
    force=True
)
logger = logging.getLogger("ai_hunter.main")

async def main():
    logger.info("Starting AI Hunter Daemon on Dell OptiPlex Server...")
    settings = Settings.load()
    
    storage = StorageEngine(settings.storage.db_path)
    heuristics = HeuristicsEngine(
        entropy_threshold=settings.heuristics.entropy_threshold,
        rate_burst_threshold=settings.heuristics.rate_burst_threshold,
        rate_window_sec=settings.heuristics.rate_window_sec
    )
    gemini = GeminiClassifier(
        api_key=settings.gemini.api_key,
        model=settings.gemini.model,
        timeout_sec=settings.gemini.timeout_sec
    )
    dispatcher = Dispatcher(settings, storage)
    ingestion = IngestionWorker(settings, storage, heuristics, gemini, dispatcher)

    loop = asyncio.get_running_loop()
    stop_event = asyncio.Event()

    def _signal_handler():
        logger.info("Shutdown signal received, initiating graceful stop...")
        stop_event.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, _signal_handler)

    # Launch ingestion polling and Home Assistant WebSocket event listener concurrently
    tasks = [
        asyncio.create_task(ingestion.run(), name="IngestionTask"),
        asyncio.create_task(dispatcher.listen_ha_websocket(), name="WebSocketTask")
    ]

    logger.info("AI Hunter Daemon initialized and active.")

    await stop_event.wait()

    logger.info("Stopping background tasks...")
    for task in tasks:
        task.cancel()
    
    await asyncio.gather(*tasks, return_exceptions=True)
    await dispatcher.close()
    logger.info("AI Hunter Daemon cleanly halted.")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except (KeyboardInterrupt, SystemExit):
        pass
