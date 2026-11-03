#!/usr/bin/env bash
# Attaques contre l'API en mode mTLS : chaque cas doit être REJETÉ.
# Usage : ./attacker/mtls_attacks.sh [--pause]   (--pause : attend Entrée entre les cas, pour commenter)
# Variables : SERVER (https://api.iiot.lab:8443)  PKI (pki/out)
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKI="${PKI:-$HERE/../pki/out}"
SERVER="${SERVER:-https://api.iiot.lab:8443}"
CA="$PKI/ca/ca.crt"
BODY='{"device_id":"edge-01","metric":"pressure_bar","value":11.5}'
PAUSE=0; [[ "${1:-}" == "--pause" ]] && PAUSE=1

attack() { # <titre> <attendu> <args curl...>
  local title="$1" expect="$2"; shift 2
  echo; echo "────────────────────────────────────────────────────────────"
  echo "▶ $title"; echo "  attendu : $expect"
  out=$(curl -sS --noproxy '*' --cacert "$CA" -X POST "$SERVER/telemetry" -H 'Content-Type: application/json' -d "$BODY" -w '\nHTTP %{http_code}' "$@" 2>&1); rc=$?
  echo "  curl exit=$rc"; echo "$out" | sed 's/^/  | /'
  [[ $PAUSE -eq 1 ]] && read -r -p "  [Entrée pour continuer] " _
}

attack "1. Aucun certificat client" \
       "alerte TLS 'certificate required' : rejet AVANT toute requête HTTP" 

attack "2. Token statique volé (valide dans le scénario vulnérable) mais sans certificat" \
       "même rejet TLS : le token n'est jamais lu" \
       -H "Authorization: Bearer $(cat "$PKI/tokens/edge-01.token" 2>/dev/null || echo token-inconnu)"

attack "3. Certificat 'edge-01' signé par une CA pirate (même CN !)" \
       "alerte TLS 'unknown ca' : le CN ne prouve rien, c'est la signature de la CA de confiance qui compte" \
       --cert "$PKI/rogue/edge-01.crt" --key "$PKI/rogue/edge-01.key"

attack "4. Nœud légitime compromis (edge-02) qui prétend être edge-01" \
       "HTTP 403 : TLS accepté, mais l'identité du certificat ≠ device_id du message" \
       --cert "$PKI/devices/edge-02/edge-02.crt" --key "$PKI/devices/edge-02/edge-02.key"
