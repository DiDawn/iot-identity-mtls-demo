"""Génère un token statique par nœud (scénario VULNÉRABLE uniquement).

Écrit server/tokens.json ({token: device_id}, lu par l'API) et pki/out/tokens/<device>.token
(copié sur le Pi : c'est ce fichier que l'attaquant va « voler »).
"""
import json
import secrets
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
devices = sys.argv[1:] or ["edge-01", "edge-02"]

out = ROOT / "pki/out/tokens"
out.mkdir(parents=True, exist_ok=True)
mapping = {}
for dev in devices:
    token = "iiot_" + secrets.token_urlsafe(24)
    mapping[token] = dev
    f = out / f"{dev}.token"
    f.write_text(token + "\n")
    f.chmod(0o600)

(ROOT / "server/tokens.json").write_text(json.dumps(mapping, indent=2) + "\n")
print(f"tokens générés pour : {', '.join(devices)}")
