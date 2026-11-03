#!/usr/bin/env bash
# Test de bout en bout (local, sans Pi) : PKI -> serveur token -> serveur mTLS -> attaques.
# Usage : make test        Sort avec un code ≠ 0 si un comportement attendu n'est pas observé.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 1
PY="${PY:-python3}"
PKI=pki/out
TP=18000 MP=18443 DP=18080
PIDS=()
FAIL=0
trap 'kill "${PIDS[@]}" 2>/dev/null; wait 2>/dev/null' EXIT

ok()   { printf '  \033[92mOK\033[0m   %s\n' "$*"; }
ko()   { printf '  \033[91mKO\033[0m   %s\n' "$*"; FAIL=1; }
check() { # <description> <attendu (regex)> <sortie>
  if grep -qE "$2" <<<"$3"; then ok "$1"; else ko "$1  (attendu /$2/, obtenu: ${3//$'\n'/ | })"; fi
}
post() { # <port> <body> [args curl...]
  local port="$1" body="$2"; shift 2
  curl -sS --noproxy '*' --cacert "$PKI/ca/ca.crt" -X POST "https://localhost:$port/telemetry" \
       -H 'Content-Type: application/json' -d "$body" -w ' HTTP %{http_code}' "$@" 2>&1
}
wait_port() { for _ in $(seq 40); do (echo > "/dev/tcp/127.0.0.1/$1") 2>/dev/null && return 0; sleep 0.25; done; return 1; }

echo "== PKI + tokens"
PKI_OUT="$PWD/$PKI" bash ./pki/make_pki.sh --force >/dev/null && ok "PKI générée" || ko "PKI"
$PY server/gen_tokens.py >/dev/null && ok "tokens générés" || ko "tokens"
TOKEN=$(cat $PKI/tokens/edge-01.token)
GOOD='{"device_id":"edge-01","metric":"pressure_bar","value":4.2}'
EVIL='{"device_id":"edge-01","metric":"pressure_bar","value":11.5}'

echo "== Scénario VULNÉRABLE (TLS simple + token)"
$PY -m server.run --mode token --port $TP --dashboard-port $DP >/tmp/e2e_token.log 2>&1 & PIDS+=($!)
wait_port $TP || ko "serveur token non démarré"
check "nœud légitime accepté"                    'HTTP 201' "$(post $TP "$GOOD" -H "Authorization: Bearer $TOKEN")"
check "token VOLÉ + fausse mesure ACCEPTÉS (faille)" '"alarm":true.*HTTP 201' "$(post $TP "$EVIL" -H "Authorization: Bearer $TOKEN")"
check "token inconnu refusé (401)"               'HTTP 401' "$(post $TP "$EVIL" -H 'Authorization: Bearer nope')"
check "requête SANS token refusée (401)"         'token manquant.*HTTP 401' "$(post $TP "$EVIL")"
check "script attaquant : 401 sans token puis 201 avec le token volé" 'HTTP 401.*HTTP 401.*HTTP 201.*HTTP 201' "$($PY attacker/replay_token.py --server https://localhost:$TP --ca $PKI/ca/ca.crt --token-file $PKI/tokens/edge-01.token --count 2 --count-no-token 2 --no-pause 2>&1 | sed 's/\x1b\[[0-9;]*m//g' | tr '\n' ' ')"
check "dashboard : rejet « aucun token » enregistré" 'HTTP 401 : aucun token' "$(curl -s --noproxy '*' http://127.0.0.1:$DP/state)"
check "dashboard : alarme visible"               '"alarm": ?true' "$(curl -s --noproxy '*' http://127.0.0.1:$DP/state)"
check "dashboard : paquet détaillé (source, en-têtes masqués, corps)" '"src": ?"[^"]+".*"authorization": ?"Bearer [^"]*…' "$(curl -s --noproxy '*' http://127.0.0.1:$DP/state)"
check "dashboard : le 401 est enregistré comme rejet" '"kind": ?"http".*HTTP 401' "$(curl -s --noproxy '*' http://127.0.0.1:$DP/state)"
kill "${PIDS[0]}"; wait "${PIDS[0]}" 2>/dev/null

echo "== Scénario SÉCURISÉ (mTLS)"
$PY -m server.run --mode mtls --port $MP --dashboard-port $DP >/tmp/e2e_mtls.log 2>&1 & PIDS+=($!)
wait_port $MP || ko "serveur mTLS non démarré"
E1="--cert $PKI/devices/edge-01/edge-01.crt --key $PKI/devices/edge-01/edge-01.key"
E2="--cert $PKI/devices/edge-02/edge-02.crt --key $PKI/devices/edge-02/edge-02.key"
RG="--cert $PKI/rogue/edge-01.crt --key $PKI/rogue/edge-01.key"
check "nœud avec certificat valide accepté"       'identity":"edge-01".*HTTP 201' "$(post $MP "$GOOD" $E1)"
check "sans certificat : alerte TLS required"     'alert certificate required' "$(post $MP "$EVIL")"
check "token volé SANS certificat : même rejet"   'alert certificate required' "$(post $MP "$EVIL" -H "Authorization: Bearer $TOKEN")"
check "certificat CA pirate (même CN) : unknown ca" 'alert unknown ca' "$(post $MP "$EVIL" $RG)"
check "edge-02 usurpe edge-01 : 403 applicatif"   'HTTP 403' "$(post $MP "$EVIL" $E2)"
STATE=$(curl -s --noproxy '*' http://127.0.0.1:$DP/state)
check "dashboard : rejets TLS enregistrés avec l'alerte"  '"kind": ?"tls".*certificate required \(116\)' "$STATE"
check "dashboard : rejet CA pirate (unknown ca)"          'unknown ca \(48\)' "$STATE"
check "dashboard : rejet 403 enregistré avec le corps"    'HTTP 403.*"value": ?11.5' "$STATE"
check "dashboard : certificat du nœud dans le paquet accepté" '"cert": ?\{"cn": ?"edge-01"' "$STATE"
check "journal serveur : identité CN/SAN extraite" 'CN=edge-01 SAN=edge-01.iiot.lab' "$(sed 's/\x1b\[[0-9;]*m//g' /tmp/e2e_mtls.log)"
check "journal serveur : rejets TLS tracés"        'handshake TLS refusé.*CERTIFICATE_VERIFY_FAILED' "$(sed 's/\x1b\[[0-9;]*m//g' /tmp/e2e_mtls.log)"

echo; [[ $FAIL -eq 0 ]] && echo "Tous les tests passent." || { echo "ÉCHEC."; exit 1; }
