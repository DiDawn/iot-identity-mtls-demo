"""API de télémétrie IIoT (FastAPI) : deux modes d'authentification des nœuds Edge.

* mode "token" (VULNÉRABLE) : TLS simple (le serveur prouve son identité, pas le client).
  Le client s'identifie par un token statique stocké sur le disque.
* mode "mtls" (SÉCURISÉ)   : TLS mutuel. Le client est authentifié par la couche transport
  (certificat X.509 signé par la CA privée) AVANT que la moindre requête HTTP soit lue.
  L'identité applicative est extraite du certificat (CN / SAN) et non du corps de la requête.
"""
from __future__ import annotations

import json
import os
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

ALERT_THRESHOLD_BAR = 8.0  # au-delà : alarme critique sur la ligne de pression

RESET, DIM, RED, GREEN, YELLOW, CYAN = "\033[0m", "\033[2m", "\033[91m", "\033[92m", "\033[93m", "\033[96m"


def log(tag: str, color: str, msg: str) -> None:
    print(f"{time.strftime('%H:%M:%S')} {color}[{tag:<7}]{RESET} {msg}", flush=True)


class Telemetry(BaseModel):
    device_id: str = Field(..., examples=["edge-01"])
    metric: str = "pressure_bar"
    value: float


@dataclass
class Store:
    """État en mémoire partagé entre l'API (port TLS) et le dashboard (localhost)."""

    mode: str
    readings: deque = field(default_factory=lambda: deque(maxlen=300))
    rejects: deque = field(default_factory=lambda: deque(maxlen=300))
    latest: dict[str, dict[str, Any]] = field(default_factory=dict)
    seq: int = 0
    n_accepted: int = 0
    n_rejected: int = 0

    def add(self, device_id: str, value: float, auth: str, identity: str, packet: dict | None = None) -> dict[str, Any]:
        self.seq += 1
        self.n_accepted += 1
        rec = {
            "id": self.seq,
            "t": time.time(),
            "device": device_id,
            "value": value,
            "auth": auth,
            "identity": identity,
            "alarm": value > ALERT_THRESHOLD_BAR,
            "packet": packet or {},
        }
        self.readings.append(rec)
        self.latest[device_id] = rec
        return rec

    def reject(self, kind: str, source: str, title: str, reason: str, packet: dict | None = None, alert: str | None = None, device: str | None = None) -> dict[str, Any]:
        """Paquet refusé : kind = "tls" (poignée de main) ou "http" (couche application)."""
        self.seq += 1
        self.n_rejected += 1
        rec = {
            "id": self.seq,
            "t": time.time(),
            "kind": kind,
            "source": source,
            "title": title,
            "reason": reason,
            "alert": alert,
            "device": device,
            "packet": packet or {},
        }
        self.rejects.append(rec)
        return rec


# --------------------------------------------------------------------------- identités


@dataclass
class Identity:
    device_id: str
    method: str  # "token" | "mtls"
    detail: str  # texte affiché dans les logs (CN/SAN ou fin du token)


def parse_peer_cert(cert: dict[str, Any]) -> dict[str, Any]:
    """Transforme le dict de ssl.getpeercert() en {cn, san_dns, san_uri, issuer_cn}."""

    def rdn_value(seq, key):
        for rdn in seq:
            for k, v in rdn:
                if k == key:
                    return v
        return None

    san = cert.get("subjectAltName", ())
    return {
        "cn": rdn_value(cert.get("subject", ()), "commonName"),
        "issuer_cn": rdn_value(cert.get("issuer", ()), "commonName"),
        "san_dns": [v for k, v in san if k == "DNS"],
        "san_uri": [v for k, v in san if k == "URI"],
        "serial": cert.get("serialNumber"),
        "not_after": cert.get("notAfter"),
    }


def mask_secret(value: str) -> str:
    """Tronque un secret au milieu (début et fin visibles) : assez pour le reconnaître à l'écran, pas pour le recopier."""
    token = value.removeprefix("Bearer ").strip()
    shown = token[:8] + "…" + token[-6:] if len(token) > 20 else "…" + token[-6:]
    return ("Bearer " if value.startswith("Bearer ") else "") + shown


def packet_of(request: Request, body: dict | None = None) -> dict[str, Any]:
    """Résumé affichable d'une requête : ce que le dashboard montre au survol d'un point."""
    peer = request.scope.get("iiot_peer") or {}
    h = request.headers
    headers = {k: h[k] for k in ("host", "content-type", "content-length", "user-agent") if k in h}
    if "authorization" in h:
        headers["authorization"] = mask_secret(h["authorization"])
    c = request.client
    cert = None
    if peer.get("cn"):
        cert = {
            "cn": peer["cn"],
            "san": peer.get("san_dns", []) + peer.get("san_uri", []),
            "issuer": peer.get("issuer_cn"),
            "serial": peer.get("serial"),
            "not_after": peer.get("not_after"),
        }
    return {
        "src": f"{c.host}:{c.port}" if c else "?",
        "request": f"{request.method} {request.url.path}",
        "tls": " · ".join(x for x in (peer.get("tls"), peer.get("cipher")) if x) or None,
        "headers": headers,
        "body": body,
        "cert": cert,
    }


def load_tokens(path: Path) -> dict[str, str]:
    """tokens.json : {"<token>": "<device_id>"}"""
    return json.loads(path.read_text()) if path.exists() else {}


def make_identity_dependency(mode: str, tokens: dict[str, str], store: Store):
    def token_identity(request: Request) -> Identity:
        auth = request.headers.get("authorization", "")
        token = auth.removeprefix("Bearer ").strip()
        device = tokens.get(token)
        if not device:
            pkt = packet_of(request)
            if token:
                log("REJECT", RED, f"HTTP 401 : token inconnu depuis {request.client.host}")
                store.reject("http", pkt["src"], "HTTP 401 : token inconnu", "le token présenté n'existe pas côté serveur", packet=pkt)
                raise HTTPException(401, "token invalide")
            log("REJECT", RED, f"HTTP 401 : aucun token depuis {request.client.host}")
            store.reject("http", pkt["src"], "HTTP 401 : aucun token", "la requête ne porte pas de token : le serveur en exige un", packet=pkt)
            raise HTTPException(401, "token manquant")
        return Identity(device, "token", f"token=…{token[-6:]}")

    def mtls_identity(request: Request) -> Identity:
        peer = request.scope.get("iiot_peer")
        if not peer or not peer.get("cn"):
            # Ne devrait jamais arriver : sans certificat valide, la connexion TLS est déjà coupée.
            log("REJECT", RED, "HTTP 401 : aucun certificat client (garde-fou applicatif)")
            raise HTTPException(401, "certificat client requis")
        detail = f"CN={peer['cn']} SAN={','.join(peer['san_dns'] + peer['san_uri'])} issuer={peer['issuer_cn']}"
        return Identity(peer["cn"], "mtls", detail)

    return token_identity if mode == "token" else mtls_identity


# --------------------------------------------------------------------------- application


def create_api(store: Store, tokens: dict[str, str]) -> FastAPI:
    app = FastAPI(title=f"IIoT API ({store.mode})", docs_url=None, redoc_url=None)
    identity_dep = make_identity_dependency(store.mode, tokens, store)

    @app.get("/health")
    def health(ident: Identity = Depends(identity_dep)):
        return {"status": "ok", "mode": store.mode, "you_are": ident.device_id}

    @app.post("/telemetry", status_code=201)
    def telemetry(payload: Telemetry, request: Request, ident: Identity = Depends(identity_dep)):
        body = payload.model_dump()
        pkt = packet_of(request, body)
        if store.mode == "mtls" and payload.device_id != ident.device_id:
            # Même authentifié, un nœud ne peut parler qu'en son nom.
            log("REJECT", RED, f"HTTP 403 : {ident.device_id} prétend être {payload.device_id}")
            store.reject(
                "http", pkt["src"], "HTTP 403 : identité du certificat ≠ device_id",
                f"le certificat est celui de {ident.device_id}, le message prétend venir de {payload.device_id}",
                packet=pkt, device=payload.device_id,
            )
            raise HTTPException(403, "device_id différent de l'identité du certificat")
        rec = store.add(payload.device_id, payload.value, ident.method, ident.detail, packet=pkt)
        tag, color = ("ALARM", RED) if rec["alarm"] else ("ACCEPT", GREEN)
        log(tag, color, f"{payload.device_id} {payload.metric}={payload.value:.2f} {DIM}auth={ident.method} {ident.detail}{RESET}")
        return {"accepted": True, "identity": ident.device_id, "alarm": rec["alarm"]}

    return app


DASHBOARD_FILE = Path(__file__).parent / "dashboard.html"


def create_dashboard(store: Store) -> FastAPI:
    """Vue lecture seule, servie en HTTP sur 127.0.0.1 : c'est l'écran projeté pendant la démo."""
    app = FastAPI(docs_url=None, redoc_url=None)

    @app.get("/", response_class=HTMLResponse)
    def index():
        return DASHBOARD_FILE.read_text(encoding="utf-8")

    @app.get("/state")
    def state():
        now = time.time()
        recent = now - 150  # le dashboard n'affiche que les 90 dernières secondes
        return {
            "mode": store.mode,
            "threshold": ALERT_THRESHOLD_BAR,
            "latest": store.latest,
            "readings": [r for r in store.readings if r["t"] >= recent],
            "rejects": [r for r in store.rejects if r["t"] >= recent],
            "counts": {"accepted": store.n_accepted, "rejected": store.n_rejected},
            "now": now,
        }

    return app
