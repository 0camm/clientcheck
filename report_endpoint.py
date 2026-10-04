# report_endpoint.py: add to your existing Render key server (Flask shown).
#
# 1. Add `requests` to the server's requirements.txt (a missing package is the
#    most common cause of "internal server error").
# 2. In the Render dashboard -> Environment, set DISCORD_WEBHOOK_URL to the FULL
#    webhook URL (https://discord.com/api/webhooks/<id>/<token>).
#    The URL is read ONLY from that environment variable. Never put it in code.
# 3. Register it once, passing your existing key check:
#       import report_endpoint
#       report_endpoint.register(app, is_valid_key)
#    is_valid_key(key, device) must return True/False using the same logic as /api/verify.
# 4. Make sure no OTHER handler or middleware already owns POST /api/report or
#    rejects it with 401 "not authenticated". If one does, it runs instead of this
#    code (register() logs an error at startup when it detects that).
#
# Quick check after deploying:  GET /api/report/health  ->  {"webhook_configured": true}
# Any failure is logged with a traceback (Render -> Logs) and returned as JSON
# instead of a bare 500, so the client shows what went wrong.

import io
import json
import logging
import os
import time
import traceback

import requests
from flask import request, jsonify

log = logging.getLogger('sentinel.report')

ROUTE = '/api/report'
MAX_LOG_CHARS = 100_000


def _webhook_url():
    return os.environ.get('DISCORD_WEBHOOK_URL', '').strip()


def _post_to_discord(webhook, payload, filename, text):
    """Posts once, honouring a single Discord rate-limit (429) retry."""
    for attempt in range(2):
        resp = requests.post(
            webhook,
            data={'payload_json': json.dumps(payload)},
            files={'files[0]': (filename, io.BytesIO(text.encode('utf-8')), 'text/plain')},
            timeout=20,
        )
        if resp.status_code == 429 and attempt == 0:
            try:
                wait = float(resp.json().get('retry_after', 1))
            except (ValueError, AttributeError):
                wait = 1.0
            time.sleep(min(wait, 5))
            continue
        return resp
    return resp


def register(app, is_valid_key):

    existing = [
        r for r in app.url_map.iter_rules()
        if r.rule == ROUTE and 'POST' in (r.methods or ())
    ]
    if existing:
        log.error(
            'POST %s is already registered (endpoint %s). That handler wins and '
            'this one will never run. Remove the old route/middleware.',
            ROUTE, existing[0].endpoint,
        )

    @app.get(ROUTE + '/health')
    def sentinel_report_health():
        return jsonify(webhook_configured=bool(_webhook_url())), 200

    @app.post(ROUTE)
    def sentinel_report():
        try:
            webhook = _webhook_url()
            if not webhook:
                log.error('DISCORD_WEBHOOK_URL is not set')
                return jsonify(error='DISCORD_WEBHOOK_URL not set on server'), 503

            data = request.get_json(silent=True) or {}

            # Accept the key from the JSON body or from headers.
            auth = request.headers.get('Authorization', '')
            bearer = auth[7:].strip() if auth.lower().startswith('bearer ') else ''
            key = str(data.get('key') or request.headers.get('X-Sentinel-Key') or bearer or '').strip()
            device = str(data.get('device') or request.headers.get('X-Sentinel-Device') or '').strip()

            discord_id = str(data.get('discord_id', '')).strip()[:20]
            host = str(data.get('host', ''))[:64]
            scan = str(data.get('scan', ''))[:32]
            text = str(data.get('log', ''))[:MAX_LOG_CHARS]

            if not key:
                return jsonify(error='missing key'), 401
            if not is_valid_key(key, device):
                return jsonify(error='invalid key'), 403
            if not discord_id.isdigit() or not text:
                return jsonify(error='bad report'), 400

            payload = {
                'content': (f'**Sentinel: {scan}**\n'
                            f'Discord ID: `{discord_id}`  |  Host: `{host}`'),
                'allowed_mentions': {'parse': []},  # logs can't ping anyone
            }
            filename = f'{scan or "scan"}_{discord_id}.txt'
            resp = _post_to_discord(webhook, payload, filename, text)

            if resp.status_code >= 300:
                log.error('Discord webhook returned %s: %s',
                          resp.status_code, resp.text[:300])
                if resp.status_code in (401, 404):
                    # Token is wrong or the webhook was deleted/regenerated.
                    return jsonify(error='webhook rejected by Discord (re-create it and update DISCORD_WEBHOOK_URL)'), 502
                return jsonify(error=f'webhook returned {resp.status_code}'), 502
            return jsonify(ok=True), 200

        except Exception as exc:
            log.error('report failed:\n%s', traceback.format_exc())
            return jsonify(error=f'{type(exc).__name__}: {exc}'), 500
