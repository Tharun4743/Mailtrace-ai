import logging
import json
import requests
from typing import List, Dict, Any
from fastapi import WebSocket
from app.config import settings

logger = logging.getLogger("mailtrace-ai")

class NotificationService:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info(f"WebSocket client connected. Active connections: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
            logger.info(f"WebSocket client disconnected. Active connections: {len(self.active_connections)}")

    async def broadcast_threat_alert(self, threat_event: Dict[str, Any]):
        """
        Broadcasts an immediate threat notification to all active browser/laptop dashboards
        and dispatches mobile push notification if configured.
        """
        message = {
            "type": "NEW_THREAT_DETECTED",
            "data": threat_event
        }
        
        # 1. Broadcast to Laptop / Browser WebSocket clients
        dead_connections = []
        for connection in self.active_connections:
            try:
                await connection.send_text(json.dumps(message))
            except Exception:
                dead_connections.append(connection)

        for dead in dead_connections:
            self.disconnect(dead)

        # 2. Dispatch Mobile Push Notification (FCM / Web Push / Webhook) if configured
        if getattr(settings, "MOBILE_PUSH_WEBHOOK_URL", None):
            try:
                requests.post(
                    settings.MOBILE_PUSH_WEBHOOK_URL,
                    json={
                        "title": f"🚨 High Risk Email Detected: {threat_event.get('subject', 'Security Alert')}",
                        "body": f"Risk Score: {threat_event.get('risk_score')}/100 | {threat_event.get('threat_type')}. {threat_event.get('sender')}",
                        "data": threat_event
                    },
                    timeout=4.0
                )
                logger.info("Mobile push notification dispatched successfully.")
            except Exception as e:
                logger.warning(f"Mobile push notification delivery skipped/failed: {str(e)}")

notification_service = NotificationService()
