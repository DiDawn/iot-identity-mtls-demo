#!/usr/bin/env python3
"""Nœud Edge - version SÉCURISÉE : TLS mutuel, le nœud présente son certificat X.509."""
import argparse
import ssl

from common import run_loop

p = argparse.ArgumentParser(description=__doc__)
p.add_argument("--server", default="https://api.iiot.lab:8443")
p.add_argument("--ca", default="/etc/iiot/pki/ca.crt")
p.add_argument("--cert", default="/etc/iiot/pki/edge-01.crt")
p.add_argument("--key", default="/etc/iiot/pki/edge-01.key", help="clé privée (ici sur la carte SD : faiblesse résiduelle !)")
p.add_argument("--device-id", default="edge-01")
p.add_argument("--interval", type=float, default=1.0)
a = p.parse_args()

ctx = ssl.create_default_context(cafile=a.ca)
ctx.load_cert_chain(certfile=a.cert, keyfile=a.key)  # preuve de possession de la clé lors du handshake
ctx.minimum_version = ssl.TLSVersion.TLSv1_3
run_loop(a.server, a.device_id, ctx, {}, a.interval, "mtls")
