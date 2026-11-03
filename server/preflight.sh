#!/usr/bin/env bash
# Vérifications avant la démo : portable (serveur IoT) et, si PI est fourni, nœud Edge.
# Ne démarre aucun serveur de la démo ; ouvre seulement deux petits écouteurs temporaires pour tester le pare-feu.
#
#   bash server/preflight.sh                               # portable + Pi (valeurs par défaut)
#   PI=noah@10.42.0.50 bash server/preflight.sh            # autre adresse du Pi
#   PI= bash server/preflight.sh                           # portable seulement
#
# Variables : PI (noah@10.42.0.167)  DEV (edge-01)  SERVER_IP (10.42.0.1)  SERVER_FQDN (api.iiot.lab)
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 1

PI="${PI-noah@10.42.0.167}"   # PI= (vide) : ne contrôler que le portable
DEV="${DEV:-edge-01}"
SERVER_FQDN="${SERVER_FQDN:-api.iiot.lab}"
SERVER_IP="${SERVER_IP:-10.42.0.1}"
FAIL=0

ok()   { printf '  \033[92mOK\033[0m   %s\n' "$*"; }
ko()   { printf '  \033[91mKO\033[0m   %s\n' "$*"; FAIL=1; }
warn() { printf '  \033[93m!!\033[0m   %s\n' "$*"; }
sec()  { printf '\n\033[96m== %s\033[0m\n' "$*"; }

sec "Portable : serveur IoT (IP $SERVER_IP)"
if [[ -x .venv/bin/python ]] && .venv/bin/python -c 'import fastapi, uvicorn' 2>/dev/null; then
  ok "environnement Python : $(.venv/bin/python --version), uvicorn $(.venv/bin/python -c 'import uvicorn; print(uvicorn.__version__)')"
else
  ko "environnement Python absent ou incomplet : bash server/setup_fedora.sh"
fi

if [[ -f pki/out/ca/ca.crt && -f pki/out/server/server.crt ]]; then
  ok "PKI présente"
  if openssl x509 -in pki/out/server/server.crt -noout -checkend 86400 >/dev/null; then ok "certificat serveur valide encore au moins 24 h"; else ko "certificat serveur expiré ou presque : make pki"; fi
  san="$(openssl x509 -in pki/out/server/server.crt -noout -ext subjectAltName 2>/dev/null)"
  if grep -q "DNS:${SERVER_FQDN}" <<<"$san"; then ok "SAN contient $SERVER_FQDN"; else ko "SAN sans $SERVER_FQDN : SERVER_IP=$SERVER_IP make pki"; fi
  if [[ -n "$SERVER_IP" ]] && grep -q "IP Address:${SERVER_IP}" <<<"$san"; then ok "SAN contient l'IP $SERVER_IP"; else warn "l'IP $SERVER_IP n'est pas dans le SAN du serveur : sans conséquence tant que les clients utilisent le nom $SERVER_FQDN (sinon : SERVER_IP=$SERVER_IP make pki puis make push-creds)"; fi
else
  ko "PKI absente : SERVER_IP=$SERVER_IP make pki"
fi
[[ -f pki/out/tokens/$DEV.token ]] && ok "token de $DEV présent" || ko "token de $DEV absent : make tokens"

if grep -qE "^[^#]*[[:space:]]${SERVER_FQDN}([[:space:]]|$)" /etc/hosts; then ok "/etc/hosts connaît $SERVER_FQDN"; else ko "/etc/hosts sans $SERVER_FQDN : bash server/setup_fedora.sh"; fi

for p in 8000 8443 8080; do
  if ss -ltn "sport = :$p" 2>/dev/null | grep -q LISTEN; then ko "le port $p est déjà utilisé (ancien serveur encore lancé ?)"; else ok "port $p libre"; fi
done

if systemctl is-active --quiet chronyd 2>/dev/null; then ok "chronyd actif : $(chronyc tracking 2>/dev/null | awk -F': ' '/Leap status/{print $2}')"; else ko "chronyd inactif : sudo systemctl enable --now chronyd"; fi
if command -v firewall-cmd >/dev/null && firewall-cmd --state >/dev/null 2>&1; then
  warn "firewalld actif : test réel depuis le Pi plus bas (zone par défaut : $(firewall-cmd --get-default-zone))"
fi

if [[ -z "$PI" ]]; then
  sec "Nœud Edge : ignoré (PI non renseigné)"
else
  sec "Nœud Edge : $PI"
  SSH=(ssh -o ConnectTimeout=6 -o ControlMaster=auto -o "ControlPath=/tmp/iiot-pf-%C" -o ControlPersist=120 "$PI")
  if ! "${SSH[@]}" true 2>/dev/null; then
    ko "connexion SSH impossible vers $PI (IP du Pi changée ? même réseau ?)"
  else
    ok "SSH fonctionne"
    LISTENERS=()
    for p in 8000 8443; do
      python3 -c 'import socket, sys, time
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", int(sys.argv[1]))); s.listen(); time.sleep(25)' "$p" 2>/dev/null &
      LISTENERS+=($!)
    done
    sleep 1
    t0=$(date +%s)
    REMOTE="$("${SSH[@]}" bash -s -- "$DEV" "$SERVER_FQDN" "$SERVER_IP" <<'REMOTE_EOF' 2>/dev/null
dev="$1"; fqdn="$2"; ip="$3"
echo "NOW=$(date +%s)"
echo "HOST=$(hostname)"
echo "RESOLVE=$(getent hosts "$fqdn" | awk '{print $1; exit}')"
for f in /etc/iiot/token /etc/iiot/pki/ca.crt "/etc/iiot/pki/$dev.crt" "/etc/iiot/pki/$dev.key"; do
  [ -r "$f" ] && echo "FILE_OK=$f" || echo "FILE_MISSING=$f"
done
if openssl verify -CAfile /etc/iiot/pki/ca.crt "/etc/iiot/pki/$dev.crt" >/dev/null 2>&1; then echo "CHAIN=ok"; else echo "CHAIN=bad"; fi
if openssl x509 -in "/etc/iiot/pki/$dev.crt" -noout -checkend 86400 >/dev/null 2>&1; then echo "CERT_LIFE=ok"; else echo "CERT_LIFE=bad"; fi
echo "SUBJECT=$(openssl x509 -in "/etc/iiot/pki/$dev.crt" -noout -subject 2>/dev/null)"
echo "NTP_REACH=$(chronyc -n sources 2>/dev/null | awk -v ip="$ip" '$2==ip {print $5; exit}')"
echo "NTP_STATE=$(chronyc tracking 2>/dev/null | awk -F': ' '/Leap status/{print $2}')"
for p in 8000 8443; do
  if python3 -c "import socket,sys; socket.create_connection(('$ip', int(sys.argv[1])), 4).close()" "$p" 2>/dev/null; then echo "PORT_$p=ok"; else echo "PORT_$p=bad"; fi
done
REMOTE_EOF
)"
    t1=$(date +%s)
    for pid in "${LISTENERS[@]}"; do kill "$pid" 2>/dev/null; done
    get() { sed -n "s/^$1=//p" <<<"$REMOTE" | head -1; }

    [[ -n "$REMOTE" ]] || ko "le Pi n'a rien répondu au contrôle"
    ok "nom d'hôte du Pi : $(get HOST)"
    now="$(get NOW)"
    if [[ -n "$now" ]]; then
      mid=$(((t0 + t1) / 2)); diff=$((now - mid)); diff=${diff#-}
      if ((diff <= 5)); then ok "heure du Pi à ${diff} s près de celle du portable"; else ko "heure du Pi décalée de ${diff} s : les certificats risquent d'être refusés (voir NTP ci-dessous)"; fi
    fi
    reach="$(get NTP_REACH)"
    if [[ -n "$reach" && "$reach" != "0" ]]; then ok "le Pi interroge bien le portable pour l'heure (Reach=$reach)"; else warn "le Pi ne synchronise pas son heure sur le portable (NTP_SERVER oublié dans provision.sh, ou 123/udp bloqué)"; fi
    [[ "$(get RESOLVE)" == "$SERVER_IP" ]] && ok "le Pi résout $SERVER_FQDN en $SERVER_IP" || ko "le Pi résout $SERVER_FQDN en « $(get RESOLVE) » au lieu de $SERVER_IP : relancer provision.sh avec SERVER_IP=$SERVER_IP"
    grep -q '^FILE_MISSING=' <<<"$REMOTE" && ko "fichiers manquants sur le Pi : $(sed -n 's/^FILE_MISSING=//p' <<<"$REMOTE" | tr '\n' ' ')→ make push-creds" || ok "token, CA, certificat et clé de $DEV présents sur le Pi"
    [[ "$(get CHAIN)" == ok ]] && ok "le certificat de $DEV est valide et signé par la CA (vérifié sur le Pi)" || ko "le certificat de $DEV ne se vérifie pas sur le Pi (heure fausse ? PKI régénérée sans make push-creds ?)"
    [[ "$(get CERT_LIFE)" == ok ]] && ok "certificat de $DEV valide encore au moins 24 h" || ko "certificat de $DEV expiré ou presque"
    for p in 8000 8443; do
      [[ "$(get PORT_$p)" == ok ]] && ok "le Pi joint le portable sur $p/tcp" || ko "le Pi ne joint pas $SERVER_IP:$p (pare-feu du portable, mauvais réseau)"
    done
    ssh -o "ControlPath=/tmp/iiot-pf-%C" -O exit "$PI" >/dev/null 2>&1
  fi
fi

echo
if ((FAIL)); then printf '\033[91mAu moins un point à corriger avant la démo.\033[0m\n'; exit 1; fi
printf '\033[92mTout est prêt.\033[0m Lancez maintenant : make test, puis la démo.\n'
