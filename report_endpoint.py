# report_endpoint.py: add this to your existing Render key server (Flask shown).
# Set DISCORD_WEBHOOK_URL as an environment variable in the Render dashboard.
# Never put the webhook URL in the client.

import io
import os
import requests
from flask import request, jsonify

WEBHOOK_URL = os.environ.get('https://discord.com/api/webhooks/1556083684950540368/LOFafcDE5RK2n9to7C3xsTXIDO2kCRr_t-sUzEGYZdDFf9CQBptQqe8tu-UOpo3WzDAR', '')


def register(app, is_valid_key):
    """is_valid_key(key, device) -> bool: reuse your existing /api/verify logic."""

    @app.post('/api/report')
    def report():
        data = request.get_json(silent=True) or {}
        key = str(data.get('key', ''))
        device = str(data.get('device', ''))
        discord_id = str(data.get('discord_id', ''))[:20]
        host = str(data.get('host', ''))[:64]
        log = str(data.get('log', ''))[:100_000]

        if not is_valid_key(key, device):
            return jsonify(error='invalid key'), 403
        if not discord_id.isdigit() or not log:
            return jsonify(error='bad report'), 400
        if not WEBHOOK_URL:
            return jsonify(error='reporting not configured'), 503

        # Neutralize mentions so a log line can't ping @everyone.
        content = (f'**Sentinel report**\nDiscord ID: `{discord_id}`\nHost: `{host}`')
        resp = requests.post(
            WEBHOOK_URL,
            data={'content': content,
                  'allowed_mentions': '{"parse": []}'},
            files={'file': (f'sentinel_{discord_id}.txt',
                            io.BytesIO(log.encode('utf-8')), 'text/plain')},
            timeout=20,
        )
        if resp.status_code >= 300:
            return jsonify(error='webhook failed'), 502
        return jsonify(ok=True), 200
