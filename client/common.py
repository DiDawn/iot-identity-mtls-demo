"""Briques communes aux clients Edge (stdlib uniquement : rien à installer sur le Pi)."""
from __future__ import annotations

import http.client
import json
import random
import ssl
import time
import urllib.parse


class PressureSensor:
    """Capteur de pression simulé : marche aléatoire autour de 4,2 bar (plage normale 3,5 à 5,5)."""

    def __init__(self, start: float = 4.2):
        self.value = start

    def read(self) -> float:
        self.value += random.uniform(-0.15, 0.15) + (4.2 - self.value) * 0.1
        return round(self.value, 2)


def post_json(server: str, path: str, payload: dict, ctx: ssl.SSLContext, headers: dict[str, str] | None = None, timeout: float = 5.0):
    """POST JSON en HTTPS. Retourne (status, corps). Les erreurs TLS remontent telles quelles."""
    u = urllib.parse.urlparse(server)
    conn = http.client.HTTPSConnection(u.hostname, u.port or 443, context=ctx, timeout=timeout)
    try:
        body = json.dumps(payload)
        h = {"Content-Type": "application/json", **(headers or {})}
        conn.request("POST", path, body=body, headers=h)
        resp = conn.getresponse()
        return resp.status, resp.read().decode(errors="replace")
    finally:
        conn.close()


def describe_error(exc: Exception) -> str:
    """Message court et pédagogique pour la démo."""
    if isinstance(exc, ssl.SSLCertVerificationError):
        return f"le CLIENT refuse le certificat du serveur : {exc.verify_message}"
    if isinstance(exc, ssl.SSLError):
        return f"alerte TLS reçue du serveur : {getattr(exc, 'reason', None) or exc}"
    if isinstance(exc, (ConnectionResetError, BrokenPipeError)):
        return f"connexion coupée par le serveur ({exc.__class__.__name__}) : rejet pendant/juste après le handshake"
    return f"{exc.__class__.__name__}: {exc}"


def run_loop(server: str, device_id: str, ctx: ssl.SSLContext, headers: dict[str, str], interval: float, label: str) -> None:
    sensor = PressureSensor()
    print(f"[{label}] {device_id} -> {server} (Ctrl-C pour arrêter)", flush=True)
    while True:
        value = sensor.read()
        stamp = time.strftime("%H:%M:%S")
        try:
            status, body = post_json(server, "/telemetry", {"device_id": device_id, "metric": "pressure_bar", "value": value}, ctx, headers)
            print(f"{stamp} pression={value:.2f} bar -> HTTP {status} {body}", flush=True)
        except (ssl.SSLError, OSError) as exc:
            print(f"{stamp} pression={value:.2f} bar -> ÉCHEC : {describe_error(exc)}", flush=True)
        time.sleep(interval)
