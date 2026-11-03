#!/usr/bin/env python3
"""Nœud Edge - version VULNÉRABLE : TLS simple + token statique lu sur le disque."""
import argparse
import ssl
from pathlib import Path

from common import run_loop

p = argparse.ArgumentParser(description=__doc__)
p.add_argument("--server", default="https://api.iiot.lab:8000")
p.add_argument("--ca", default="/etc/iiot/pki/ca.crt", help="CA qui a signé le certificat du serveur")
p.add_argument("--token-file", default="/etc/iiot/token")
p.add_argument("--device-id", default="edge-01")
p.add_argument("--interval", type=float, default=1.0)
a = p.parse_args()

token = Path(a.token_file).read_text().strip()  # <- le secret est en clair sur la carte SD
ctx = ssl.create_default_context(cafile=a.ca)   # vérifie le SERVEUR (nom + CA), rien de plus
run_loop(a.server, a.device_id, ctx, {"Authorization": f"Bearer {token}"}, a.interval, "token")
