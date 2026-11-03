#!/usr/bin/env bash
# Prépare le SERVEUR IoT sous Fedora : paquets, environnement Python, nom de l'API, pare-feu, serveur de temps.
# À lancer depuis le dépôt, en utilisateur normal (le script appelle sudo quand il en a besoin) :
#     bash server/setup_fedora.sh
# Idempotent : on peut le relancer (par exemple quand l'IP du portable change).
#
# Variables facultatives
#   SERVER_IP    IP du portable vue par le Pi                      (10.42.0.1 : câble Ethernet direct)
#   SERVER_FQDN  nom DNS de l'API                                  (api.iiot.lab)
#   LAN_CIDR     réseau autorisé à interroger l'horloge            (le /24 de SERVER_IP)
#   FW_ZONE      zone firewalld à ouvrir                           (zone de l'interface, sinon zone par défaut)
#   PERMANENT    1 = règles de pare-feu permanentes                (défaut : temporaires, effacées au redémarrage)
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

SERVER_FQDN="${SERVER_FQDN:-api.iiot.lab}"
SERVER_IP="${SERVER_IP:-10.42.0.1}"

step() { printf '\n\033[96m==> %s\033[0m\n' "$*"; }
ok()   { printf '  \033[92mOK\033[0m   %s\n' "$*"; }
warn() { printf '  \033[93m!!\033[0m   %s\n' "$*"; }
die()  { printf '  \033[91mKO\033[0m   %s\n' "$*" >&2; exit 1; }

[[ $EUID -ne 0 ]] || die "Ne pas lancer en root : le script utilise sudo quand il en a besoin."
command -v dnf >/dev/null || die "dnf introuvable : ce script vise Fedora."
sudo -v || die "sudo est nécessaire (paquets, pare-feu, /etc/hosts, chrony)."

step "Adresse du portable (celle que le Pi doit joindre)"
IFACE="$(ip -4 -o addr show | awk -v ip="$SERVER_IP" 'index($4, ip "/") == 1 {print $2; exit}')"
if [[ -z "$IFACE" ]]; then
  warn "Aucune interface ne porte $SERVER_IP : le lien vers le Pi n'est pas actif."
  warn "Câble : nmcli con up iiot-lab (voir docs/DEMO_REPRODUCTION.md, §3). Autre réseau : relancer avec SERVER_IP=<IP du portable>."
  ip -4 -o addr show scope global | awk '{print "      " $2 "  " $4}'
  die "SERVER_IP=$SERVER_IP introuvable sur ce portable."
fi
LAN_CIDR="${LAN_CIDR:-${SERVER_IP%.*}.0/24}"
ok "SERVER_IP=$SERVER_IP (interface $IFACE), réseau autorisé pour l'heure : $LAN_CIDR"

step "Paquets"
need=()
for p in python3 python3-pip openssl curl make openssh-clients chrony; do
  rpm -q "$p" >/dev/null 2>&1 || need+=("$p")
done
if ((${#need[@]})); then sudo dnf install -y "${need[@]}"; else ok "tout est déjà installé"; fi
ok "$(python3 --version) (testé avec 3.13 et 3.14)"

step "Environnement Python (.venv)"
[[ -x .venv/bin/python ]] || python3 -m venv .venv
.venv/bin/pip install -q -r requirements.txt
.venv/bin/python -c 'import fastapi, uvicorn; print("  OK   fastapi", fastapi.__version__, "/ uvicorn", uvicorn.__version__)'

step "Nom de l'API : $SERVER_FQDN -> 127.0.0.1 (pour le terminal de l'attaquant)"
if grep -qE "^[^#]*[[:space:]]${SERVER_FQDN}([[:space:]]|$)" /etc/hosts; then
  ok "entrée déjà présente"
else
  echo "127.0.0.1 $SERVER_FQDN" | sudo tee -a /etc/hosts >/dev/null && ok "entrée ajoutée"
fi

step "Pare-feu : 8000/tcp, 8443/tcp (API) et 123/udp (heure)"
if command -v firewall-cmd >/dev/null && sudo firewall-cmd --state >/dev/null 2>&1; then
  zone="${FW_ZONE:-}"
  if [[ -z "$zone" && -n "$IFACE" ]]; then zone="$(sudo firewall-cmd --get-zone-of-interface="$IFACE" 2>/dev/null || true)"; fi
  if [[ -z "$zone" || "$zone" == "no zone" ]]; then zone="$(sudo firewall-cmd --get-default-zone)"; fi
  perm=(); [[ "${PERMANENT:-0}" == 1 ]] && perm=(--permanent)
  sudo firewall-cmd "${perm[@]}" --zone="$zone" --add-port=8000/tcp --add-port=8443/tcp --add-port=123/udp >/dev/null
  ok "ports ouverts dans la zone « $zone » ($([[ ${#perm[@]} -gt 0 ]] && echo permanent || echo "temporaire : effacé au redémarrage ou au rechargement"))"
else
  ok "firewalld inactif : rien à ouvrir"
fi

step "Serveur de temps (chrony) : le Raspberry Pi 3 n'a pas d'horloge matérielle"
conf=/etc/chrony.d/iiot.conf
sudo mkdir -p /etc/chrony.d
sudo tee "$conf" >/dev/null <<EOF
# Serveur de temps de la démonstration IIoT (généré par server/setup_fedora.sh)
allow $LAN_CIDR
# Reste une source valable pour le Pi même sans Internet
local stratum 10
EOF
if ! grep -qE '^[[:space:]]*(confdir|include)[[:space:]]+/etc/chrony\.d' /etc/chrony.conf; then
  warn "/etc/chrony.conf n'inclut pas /etc/chrony.d : ajout de la directive"
  echo "confdir /etc/chrony.d" | sudo tee -a /etc/chrony.conf >/dev/null
fi
sudo systemctl enable --now chronyd >/dev/null 2>&1 || true
sudo systemctl restart chronyd
sleep 1
ok "chronyd actif ; $(chronyc tracking 2>/dev/null | awk -F': ' '/Leap status/{print "état de l horloge : " $2}')"

cat <<EOF

────────────────────────────────────────────────────────────
Serveur prêt. Suite, depuis la racine du dépôt :
  make test                                   # 20 vérifications locales
  make pki                                    # CA + certificats
  make push-code
  ssh -t noah@10.42.0.167 "sudo bash ~/iiot/pi/provision.sh"
  make push-creds
  bash server/preflight.sh
────────────────────────────────────────────────────────────
EOF
