#!/usr/bin/env bash
# Mini-PKI IIoT pour la démo : CA privée -> certificat serveur + certificats clients (nœuds Edge).
# Génère aussi une "CA pirate" et un certificat pirate portant le MÊME CN qu'un vrai nœud,
# pour montrer que le nom ne suffit pas : seule la signature de la CA de confiance compte.
#
# Usage : ./pki/make_pki.sh [--force]
# Variables : SERVER_FQDN (api.iiot.lab) SERVER_IP (10.42.0.1) DEVICES ("edge-01 edge-02") PKI_OUT
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="${PKI_OUT:-$HERE/out}"
SERVER_FQDN="${SERVER_FQDN:-api.iiot.lab}"
SERVER_IP="${SERVER_IP:-10.42.0.1}"
DEVICES="${DEVICES:-edge-01 edge-02}"
ORG="IIoT Lab"
DAYS_CA=3650
DAYS_LEAF=365

if [[ -d "$OUT" && "${1:-}" != "--force" ]]; then
  echo "PKI déjà présente dans $OUT (relancer avec --force pour tout régénérer)." >&2
  exit 0
fi
rm -rf "$OUT"
umask 077
mkdir -p "$OUT"/{ca,server,devices,rogue}

genkey() { openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1" 2>/dev/null; }

# new_ca <dir> <common name>
new_ca() {
  local dir="$1" cn="$2"
  genkey "$dir/ca.key"
  openssl req -x509 -new -key "$dir/ca.key" -sha256 -days "$DAYS_CA" \
    -subj "/O=$ORG/CN=$cn" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -addext "subjectKeyIdentifier=hash" \
    -out "$dir/ca.crt"
}

# issue <ca dir> <out prefix> <subject CN> <extensions>
issue() {
  local cadir="$1" prefix="$2" cn="$3" ext="$4"
  genkey "$prefix.key"
  openssl req -new -key "$prefix.key" -subj "/O=$ORG/CN=$cn" -out "$prefix.csr"
  openssl x509 -req -in "$prefix.csr" -CA "$cadir/ca.crt" -CAkey "$cadir/ca.key" \
    -CAcreateserial -CAserial "$cadir/ca.srl" -sha256 -days "$DAYS_LEAF" \
    -extfile <(printf '%s\n' "$ext") -out "$prefix.crt" 2>/dev/null
  rm -f "$prefix.csr"
}

server_ext() {
  printf '%s\n' \
    "basicConstraints=critical,CA:FALSE" \
    "keyUsage=critical,digitalSignature" \
    "extendedKeyUsage=serverAuth" \
    "subjectAltName=DNS:$SERVER_FQDN,DNS:localhost,IP:$SERVER_IP,IP:127.0.0.1" \
    "subjectKeyIdentifier=hash"
}

client_ext() { # $1 = device id
  printf '%s\n' \
    "basicConstraints=critical,CA:FALSE" \
    "keyUsage=critical,digitalSignature" \
    "extendedKeyUsage=clientAuth" \
    "subjectAltName=DNS:$1.iiot.lab,URI:urn:iiot:device:$1" \
    "subjectKeyIdentifier=hash"
}

echo "==> CA racine privée"
new_ca "$OUT/ca" "IIoT Lab Root CA"

echo "==> Certificat serveur ($SERVER_FQDN / $SERVER_IP)"
issue "$OUT/ca" "$OUT/server/server" "$SERVER_FQDN" "$(server_ext)"

for dev in $DEVICES; do
  echo "==> Certificat client : $dev"
  mkdir -p "$OUT/devices/$dev"
  issue "$OUT/ca" "$OUT/devices/$dev/$dev" "$dev" "$(client_ext "$dev")"
done

echo "==> CA pirate + faux certificat 'edge-01' (même CN, autre CA)"
new_ca "$OUT/rogue" "Totally Legit CA"
issue "$OUT/rogue" "$OUT/rogue/edge-01" "edge-01" "$(client_ext edge-01)"

# Les clés privées ne doivent être lisibles que par leur propriétaire
find "$OUT" -name '*.key' -exec chmod 600 {} +

echo
echo "PKI générée dans : $OUT"
echo "  CA de confiance : $OUT/ca/ca.crt"
echo "  Serveur         : $OUT/server/server.{crt,key}"
echo "  Clients         : $OUT/devices/<id>/<id>.{crt,key}"
echo "  Pirate          : $OUT/rogue/edge-01.{crt,key} (signé par une CA inconnue)"
