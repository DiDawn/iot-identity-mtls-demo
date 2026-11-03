#!/usr/bin/env bash
# Provisioning du nœud Edge (Raspberry Pi OS Lite 64 bits / Debian 13).
# À exécuter SUR le Pi :   sudo ./pi/provision.sh      (par défaut : serveur et NTP en 10.42.0.1)
# Idempotent : peut être relancé sans risque (par ex. quand l'IP du portable change).
#
# Variables (toutes facultatives)
#   HOSTNAME_NEW  nom d'hôte du nœud                      (edge-01)
#   SERVER_FQDN   nom DNS de l'API                        (api.iiot.lab)
#   SERVER_IP     IP du portable : ajoute l'entrée /etc/hosts (défaut 10.42.0.1 ; vide = ne rien faire)
#   NTP_SERVER    serveur NTP (chrony du portable) : le Pi n'a pas d'horloge matérielle (défaut = SERVER_IP ; vide = défaut Debian)
#   TZ_NEW        fuseau horaire                          (Europe/Paris)
set -euo pipefail

[[ $EUID -eq 0 ]] || { echo "À lancer avec sudo." >&2; exit 1; }

HOSTNAME_NEW="${HOSTNAME_NEW:-edge-01}"
SERVER_FQDN="${SERVER_FQDN:-api.iiot.lab}"
SERVER_IP="${SERVER_IP:-10.42.0.1}"
NTP_SERVER="${NTP_SERVER:-$SERVER_IP}"
TZ_NEW="${TZ_NEW:-Europe/Paris}"
EDGE_USER="${SUDO_USER:-noah}"
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

step() { printf '\n==> %s\n' "$*"; }

step "Nom d'hôte : $HOSTNAME_NEW / fuseau : $TZ_NEW"
hostnamectl set-hostname "$HOSTNAME_NEW"
timedatectl set-timezone "$TZ_NEW"
if grep -qE '^127\.0\.1\.1' /etc/hosts; then
  sed -i -E "s/^127\.0\.1\.1.*/127.0.1.1\t$HOSTNAME_NEW/" /etc/hosts
else
  printf '127.0.1.1\t%s\n' "$HOSTNAME_NEW" >> /etc/hosts
fi
# Si cloud-init est présent, l'empêcher de remettre l'ancien nom au prochain démarrage.
if [[ -d /etc/cloud/cloud.cfg.d ]]; then
  echo "preserve_hostname: true" > /etc/cloud/cloud.cfg.d/99-iiot-preserve-hostname.cfg
fi

step "Paquets : chrony (NTP), python3, openssl, curl"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq chrony python3 openssl curl

if [[ -n "$NTP_SERVER" ]]; then
  step "chrony : synchronisation sur $NTP_SERVER (saut d'horloge autorisé à tout moment)"
  cat > /etc/chrony/conf.d/iiot.conf <<CONF
# Le Pi 3B n'a pas de RTC : au démarrage, l'horloge est fausse tant que NTP n'a pas répondu.
# Sans heure correcte, les certificats sont rejetés ("not yet valid" / "expired").
server $NTP_SERVER iburst prefer minpoll 2 maxpoll 4
makestep 1 -1
CONF
  systemctl restart chrony
fi

if [[ -n "$SERVER_IP" ]]; then
  step "/etc/hosts : $SERVER_FQDN -> $SERVER_IP"
  sed -i "/[[:space:]]$SERVER_FQDN\$/d" /etc/hosts
  printf '%s\t%s\n' "$SERVER_IP" "$SERVER_FQDN" >> /etc/hosts
fi

step "Répertoires de configuration du nœud (/etc/iiot)"
install -d -m 0750 -o "$EDGE_USER" -g "$EDGE_USER" /etc/iiot
install -d -m 0700 -o "$EDGE_USER" -g "$EDGE_USER" /etc/iiot/pki

if [[ -d "$REPO/client" ]]; then
  step "Clients Edge -> /opt/iiot/client"
  install -d -m 0755 /opt/iiot/client
  cp -r "$REPO/client/." /opt/iiot/client/
  chmod +x /opt/iiot/client/*.py
fi

step "État final"
echo "hostname : $(hostname)   fuseau : $(timedatectl show -p Timezone --value)"
echo "heure    : $(date)   synchronisée : $(timedatectl show -p NTPSynchronized --value)"
command -v chronyc >/dev/null && chronyc tracking | sed -n '1,5p' || true
echo "Terminé. Un redémarrage n'est pas indispensable."
