"""WebSocket endpoint for real-time VPN connection monitoring."""

import asyncio
import json
import logging
from typing import Set

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from backend.core.monitor import ConnectionMonitor

logger = logging.getLogger(__name__)

router = APIRouter()

# Active WebSocket clients
active_connections: Set[WebSocket] = set()


@router.websocket("/ws/monitor")
async def monitor_websocket(websocket: WebSocket) -> None:
    """Stream real-time connection state to WebSocket clients.

    Accepts the WebSocket connection, adds it to the active clients set,
    then continuously sends JSON state dicts from ConnectionMonitor.stream().
    Cleans up on disconnect or error.
    """
    await websocket.accept()
    active_connections.add(websocket)
    logger.info("WebSocket client connected. Active clients: %d", len(active_connections))

    monitor = ConnectionMonitor()
    try:
        async for state in monitor.stream():
            try:
                await websocket.send_json(state)
            except WebSocketDisconnect:
                break
            except Exception:
                logger.exception("Error sending to WebSocket client")
                break
    except WebSocketDisconnect:
        pass
    except asyncio.CancelledError:
        pass
    except Exception:
        logger.exception("Error in monitor stream")
    finally:
        active_connections.discard(websocket)
        logger.info("WebSocket client disconnected. Active clients: %d", len(active_connections))
