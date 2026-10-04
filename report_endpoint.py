# report_endpoint.py: add to your existing Render key server (Flask shown).
#
# 1. Add `requests` to the server's requirements.txt (a missing package is the
#    most common cause of "internal server error").
# 2. In the Render dashboard -> Environment, set DISCORD_WEBHOOK_URL to the FULL
#    webhook URL (https://discord.com/api/webhooks/<id>/<token>).
# 3. Register it once, passing your existing key check:
#       import report_endpoint
#       report_endpoint.register(app, is_valid_key)
#    is_valid_key(key, device) must return True/False using the same logic as /api/verify.
#
# Any failure is logged with a traceback (Render -> Logs) and returned as JSON
# instead of a bare 500, so the client shows what went wrong.

import io
import json
import logging
import os
import traceback

import requests
from flask import request, jsonify

log = logging.getLogger('sentinel.report')


def register(app, is_valid_key):

    @app.post('/api/report')
    def report():
        try:
            webhook = os.environ.get('DISCORD_WEBHOOK_URL', 'https://discord.com/api/webhooks/1556083684950540368/LOFafcDE5RK2n9to7C3xsTXIDO2kCRr_t-sUzEGYZdDFf9CQBptQqe8tu-UOpo3WzDAR').strip()
            if not webhook:
                return jsonify(error='DISCORD_WEBHOOK_URL not set on server'), 503

            data = request.get_json(silent=True) or {}
            key = str(data.get('key', ''))
            device = str(data.get('device', ''))
            discord_id = str(data.get('discord_id', ''))[:20]
            host = str(data.get('host', ''))[:64]
            scan = str(data.get('scan', ''))[:32]
            text = str(data.get('log', ''))[:100_000]

            if not is_valid_key(key, device):
                return jsonify(error='invalid key'), 403
            if not discord_id.isdigit() or not text:
                return jsonify(error='bad report'), 400

            payload = {
                'content': (f'**Sentinel: {scan}**\n'
                            f'Discord ID: `{discord_id}`  |  Host: `{host}`'),
                'allowed_mentions': {'parse': []},  # logs can't ping anyone
            }
            resp = requests.post(
                webhook,
                data={'payload_json': json.dumps(payload)},
                files={'files[0]': (f'{scan or "scan"}_{discord_id}.txt',
                                    io.BytesIO(text.encode('utf-8')),
                                    'text/plain')},
                timeout=20,
            )
            if resp.status_code >= 300:
                log.error('Discord webhook returned %s: %s',
                          resp.status_code, resp.text[:300])
                return jsonify(error=f'webhook returned {resp.status_code}'), 502
            return jsonify(ok=True), 200

        except Exception as exc:
            log.error('report failed:\n%s', traceback.format_exc())
            return jsonify(error=f'{type(exc).__name__}: {exc}'), 500
