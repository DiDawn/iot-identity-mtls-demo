"""Lance l'API IIoT + le dashboard.

    python -m server.run --mode token   # scénario vulnérable (TLS simple + token statique)
    python -m server.run --mode mtls    # scénario sécurisé  (TLS mutuel, certificat client requis)

Uvicorn n'expose pas le certificat client dans le scope ASGI : on sous-classe le protocole HTTP
pour lire `ssl_object.getpeercert()` à l'établissement de la connexion (la poignée de main TLS
est alors déjà terminée et validée) et l'injecter dans chaque requête sous `scope["iiot_peer"]`.
"""
from __future__ import annotations

import argparse
import asyncio
import ssl
from pathlib import Path

import uvicorn
from uvicorn.protocols.http.h11_impl import H11Protocol

from .app import RED, RESET, Store, create_api, create_dashboard, load_tokens, log, parse_peer_cert

ROOT = Path(__file__).resolve().parent.parent


class PeerCertMiddleware:
    """Ajoute l'identité X.509 du pair TLS au scope ASGI de chaque requête de la connexion."""

    def __init__(self, app, peer: dict):
        self.app, self.peer = app, peer

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            scope["iiot_peer"] = self.peer
        await self.app(scope, receive, send)


class PeerCertProtocol(H11Protocol):
    def connection_made(self, transport):
        super().connection_made(transport)
        sslobj = transport.get_extra_info("ssl_object")
        peer: dict = {"cn": None, "issuer_cn": None, "san_dns": [], "san_uri": []}
        if sslobj is not None:
            cert = sslobj.getpeercert()
            if cert:
                peer = parse_peer_cert(cert)
                log("TLS", "\033[96m", f"handshake OK depuis {self.client[0]} : {sslobj.version()} CN={peer['cn']} issuer={peer['issuer_cn']}")
            cipher = sslobj.cipher()
            peer["tls"], peer["cipher"] = sslobj.version(), (cipher[0] if cipher else None)
        self.app = PeerCertMiddleware(self.app, peer)


# Appelée à chaque handshake refusé : serve() y branche le Store, pour que le dashboard affiche aussi les rejets.
REJECT_SINK = None


def tls_alert_for(text: str) -> str | None:
    """Alerte TLS que le serveur envoie au client, déduite du motif OpenSSL (indicatif, pour l'affichage)."""
    t = text.lower()
    if "did not return a certificate" in t:
        return "certificate required (116)"
    if "unable to get local issuer" in t or "self-signed" in t or "self signed" in t:
        return "unknown ca (48)"
    if "expired" in t:
        return "certificate expired (45)"
    if "certificate verify failed" in t or "not yet valid" in t:
        return "bad certificate (42)"
    return None


def install_tls_reject_hook() -> None:
    """Journalise les handshakes TLS refusés ET envoie l'alerte TLS au client avant de couper.

    Par défaut, asyncio ferme la socket sans vider l'alerte TLS déjà produite par OpenSSL : le client
    voit un simple « connection reset / unexpected EOF » au lieu de `certificate required` ou
    `unknown ca`. On vide donc le BIO sortant avant la fermeture (API interne d'asyncio : si elle
    change, le hook se désactive et seule la pédagogie du message client est dégradée).
    """
    from asyncio import sslproto

    original = getattr(sslproto.SSLProtocol, "_on_handshake_complete", None)
    if original is None or not hasattr(sslproto.SSLProtocol, "_process_outgoing"):
        return

    def patched(self, handshake_exc):
        if handshake_exc is not None and getattr(self, "_server_side", False):
            peer = self._transport.get_extra_info("peername") if self._transport else None
            reason = getattr(handshake_exc, "reason", None) or str(handshake_exc)
            log("REJECT", RED, f"handshake TLS refusé depuis {peer[0] if peer else '?'} : {reason}  (aucune requête HTTP lue)")
            if REJECT_SINK is not None:
                try:
                    REJECT_SINK(f"{peer[0]}:{peer[1]}" if peer else "?", str(reason), tls_alert_for(f"{reason} {handshake_exc}"))
                except Exception:
                    pass
            try:
                self._process_outgoing()  # envoie l'alerte TLS avant la fermeture
            except Exception:
                pass
        return original(self, handshake_exc)

    sslproto.SSLProtocol._on_handshake_complete = patched


async def serve(args: argparse.Namespace) -> None:
    pki = Path(args.pki)
    store = Store(mode=args.mode)
    tokens = load_tokens(Path(args.tokens))

    def on_tls_reject(source: str, reason: str, alert: str | None) -> None:
        store.reject("tls", source, "Connexion rejetée : poignée de main TLS", reason, alert=alert, packet={"src": source, "headers": {}, "body": None, "cert": None})

    global REJECT_SINK
    REJECT_SINK = on_tls_reject

    api_kwargs: dict = dict(
        host=args.host,
        port=args.port,
        ssl_certfile=str(pki / "server/server.crt"),
        ssl_keyfile=str(pki / "server/server.key"),
        log_level="warning",
        access_log=False,
        loop="asyncio",
        http=PeerCertProtocol,  # lit le certificat du pair (mTLS) et la version TLS, pour l'identité et le dashboard
    )
    if args.mode == "mtls":
        api_kwargs.update(ssl_ca_certs=str(pki / "ca/ca.crt"), ssl_cert_reqs=ssl.CERT_REQUIRED)

    api = uvicorn.Server(uvicorn.Config(create_api(store, tokens), **api_kwargs))
    dash = uvicorn.Server(
        uvicorn.Config(create_dashboard(store), host="127.0.0.1", port=args.dashboard_port, log_level="warning", access_log=False, loop="asyncio")
    )
    # uvicorn installe ses propres handlers de signaux ; on les laisse au premier serveur seulement.
    dash.install_signal_handlers = lambda: None  # type: ignore[method-assign]

    label = "TLS mutuel (certificat client OBLIGATOIRE)" if args.mode == "mtls" else "TLS simple + token statique (VULNÉRABLE)"
    log("START", "\033[93m", f"API  https://{args.host}:{args.port}  mode={args.mode} : {label}")
    log("START", "\033[93m", f"Dashboard  http://127.0.0.1:{args.dashboard_port}")
    await asyncio.gather(api.serve(), dash.serve())


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--mode", choices=["token", "mtls"], required=True)
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--port", type=int, help="défaut : 8000 (token) / 8443 (mtls)")
    p.add_argument("--dashboard-port", type=int, default=8080)
    p.add_argument("--pki", default=str(ROOT / "pki/out"))
    p.add_argument("--tokens", default=str(ROOT / "server/tokens.json"))
    args = p.parse_args()
    args.port = args.port or (8443 if args.mode == "mtls" else 8000)

    install_tls_reject_hook()
    try:
        asyncio.run(serve(args))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
