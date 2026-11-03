# Identité des objets IIoT : du token statique au mTLS

Un objet connecté industriel envoie des mesures à un serveur. **Comment le serveur sait-il que c'est bien cet objet ?**
Ce dépôt permet de le vérifier par l'expérience : on vole l'identité d'un capteur, puis on la rend infalsifiable.

## Objectifs

À la fin de la démonstration, vous saurez :

1. expliquer pourquoi un **token statique** stocké sur l'objet est une identité faible (vol, copie, rejeu) ;
2. distinguer **TLS simple** (le serveur prouve qui il est) et **TLS mutuel** (le client aussi) ;
3. lire un certificat **X.509** (CN, SAN, usage de clé) et dire qui l'a signé et pourquoi on lui fait confiance ;
4. observer où se fait le rejet d'un intrus : **dans la couche transport, avant toute requête HTTP** ;
5. identifier ce que cette protection **ne couvre pas** : la clé privée, si elle est lisible sur le disque de l'objet.

## Les trois rôles

| Rôle | Ce que c'est | Dans la démo |
|---|---|---|
| **Nœud Edge** | L'objet connecté (passerelle industrielle) qui envoie la pression d'une ligne | Un Raspberry Pi, ou toute machine Linux |
| **Serveur IoT** | L'API centrale qui reçoit les mesures et affiche la supervision | Un PC Linux, FastAPI + Uvicorn |
| **Attaquant** | Quelqu'un qui a un accès physique au nœud (carte SD retirée) ou au réseau | Un terminal séparé |

```
  Nœud Edge ──── HTTPS ────▶ Serveur IoT (API FastAPI) ───▶ Dashboard http://127.0.0.1:8080
  /etc/iiot/token             mode token : lit l'en-tête Authorization
  /etc/iiot/pki/*.crt,*.key   mode mtls  : exige un certificat client valide, lit son CN/SAN
```

| | Scénario A : **vulnérable** | Scénario B : **sécurisé** |
|---|---|---|
| Transport | TLS simple | **TLS mutuel (mTLS)** |
| Identité du nœud | token statique sur le disque | certificat X.509 signé par une CA privée |
| Port de l'API | 8000 | 8443 |
| Un attaquant qui a copié le secret | injecte de fausses mesures | est rejeté avant le moindre octet HTTP |

## Mini-glossaire

| Terme | À retenir |
|---|---|
| **Identité d'un objet** | Ce qui permet de dire « c'est bien *cet* équipement ». Elle se prouve, elle ne se déclare pas. |
| **Token statique** | Un secret partagé, identique à chaque connexion. Qui le copie *est* l'objet. |
| **CA privée** | L'autorité interne qui signe les certificats. Le serveur n'accepte que ceux qu'elle a signés. |
| **Certificat X.509** | Une clé publique + une identité (CN, SAN) + une signature de la CA. Il se partage sans risque. |
| **Clé privée** | Le secret qui prouve qu'on possède le certificat. **Elle ne doit jamais quitter l'objet.** |
| **CN / SAN** | Nom du sujet / noms alternatifs du certificat. Ici : l'identifiant du nœud (`edge-01`). |
| **mTLS** | Le serveur *et* le client présentent un certificat pendant la poignée de main TLS. |
| **EKU** | Usage autorisé du certificat : `serverAuth` ou `clientAuth`. Un certificat serveur ne peut pas faire office de client. |

## Prérequis

- Un **serveur IoT** : Linux avec `python3` (testé avec 3.13 et 3.14), `openssl`, `curl`, `make`.
- Un **nœud Edge** : Raspberry Pi OS Lite 64 bits (Debian 13), accessible en SSH. Python 3 suffit, aucun paquet à installer.
- Les deux machines se joignent sur un même réseau (switch, box ou câble Ethernet direct). Notez l'**IP du serveur IoT** : `<IP-SERVEUR>`.
- L'horloge des machines doit être correcte (voir « Le piège de l'horloge »).

## 1. Préparer le serveur IoT

```bash
make venv                                                   # environnement Python + FastAPI/Uvicorn
echo "127.0.0.1 api.iiot.lab" | sudo tee -a /etc/hosts       # nom de l'API, pour l'attaquant local
SERVER_IP=<IP-SERVEUR> make pki                             # CA, certificat serveur, certificats clients, CA pirate
```

> **Compatibilité.** La démonstration a été testée sous **Fedora** (serveur) avec un Raspberry Pi 3B. La PKI, l'API, les clients, les attaques et `make test` sont du Python/OpenSSL standard
> (`make test` a aussi été exécuté sur Ubuntu 24.04), mais le réseau, le pare-feu et le serveur de temps n'ont été éprouvés que sous Fedora :
> **je ne peux pas garantir une reproductibilité parfaite sur une autre distribution.**

Pour **reproduire la démonstration de zéro** (matériel, réseau, vérifications, déroulé), suivez [`docs/DEMO_REPRODUCTION.md`](docs/DEMO_REPRODUCTION.md). Sous Fedora, `bash server/setup_fedora.sh` fait tout ce qui précède (hors PKI), ouvre les ports du pare-feu et configure
`chrony` comme serveur de temps ; ailleurs, les équivalents sont au §10 du guide.
Par défaut, tous les scripts supposent `SERVER_IP=10.42.0.1` (câble Ethernet direct) ; passez `SERVER_IP=<IP-SERVEUR>` sur un autre réseau.

`make pki` crée tout dans `pki/out/` (jamais versionné) : relancez-le pour repartir de zéro.
Si un pare-feu est actif, ouvrez les ports `8000/tcp` et `8443/tcp`.

*Exemple de réseau direct (câble Ethernet entre le serveur et le nœud), avec NetworkManager* : le serveur fait office de DHCP.

```bash
nmcli con add type ethernet ifname <interface> con-name iiot-lab ipv4.method shared ipv4.addresses 10.42.0.1/24
nmcli con up iiot-lab
```

## 2. Préparer le nœud Edge

Depuis le serveur IoT (`PI` = adresse SSH du nœud, par exemple `utilisateur@10.42.0.50`) :

```bash
make push-code  PI=<utilisateur@adresse-du-noeud>             # copie client/ et pi/
ssh -t <utilisateur@adresse-du-noeud> \
  "sudo SERVER_IP=<IP-SERVEUR> NTP_SERVER=<IP-SERVEUR> bash ~/iiot/pi/provision.sh"
make push-creds PI=<utilisateur@adresse-du-noeud> DEV=edge-01  # CA + certificat + clé + token du nœud
```

Le Makefile vise par défaut `PI=noah@10.42.0.167` : passez `PI=` si l'adresse du nœud est différente.
Avant la démonstration, vérifiez l'ensemble (heure, certificats, pare-feu, accès du nœud aux ports du serveur) :

```bash
bash server/preflight.sh      # PI=<utilisateur@adresse> si l'adresse du nœud diffère
```

`provision.sh` règle le nom d'hôte, le fuseau, l'horloge (chrony), l'entrée `api.iiot.lab` et crée `/etc/iiot`.
Il est **idempotent** : relancez-le si l'IP du serveur change.

> **Le piège de l'horloge.** Un Raspberry Pi 3 n'a pas d'horloge matérielle. Au démarrage sans réseau NTP, sa date est fausse,
> et un certificat « pas encore valide » est refusé. Pour le serveur IoT, faire tourner `chrony` avec `allow <réseau>` et
> `local stratum 10` permet de caler le nœud même sans Internet.

## 3. Scénario A : l'identité vole en éclats

Disposez trois terminaux : **A** serveur IoT, **B** nœud Edge (SSH), **C** attaquant. Ouvrez le dashboard `http://127.0.0.1:8080`.

```bash
# A — serveur en mode vulnérable
make run-token
# B — le nœud envoie sa pression (≈ 4,2 bar)
python3 /opt/iiot/client/edge_token.py --server https://api.iiot.lab:8000
# B (second terminal) — l'attaquant retire la carte SD... ou plus simplement :
cat /etc/iiot/token
# C — l'attaquant, en deux phases (Entrée entre les deux) :
#     1. 4 paquets SANS token  -> HTTP 401 « token manquant » (✕ orange sur le dashboard)
#     2. rejeu du token volé   -> HTTP 201, fausse pression de 11,5 bar
make attack-token
```

**À observer**
- Phase 1 : sans token, le serveur refuse (401) : l'API est bien « protégée »… tant qu'on ne possède pas le secret.
- Phase 2 : la courbe monte à 11,5 bar et l'alarme passe au rouge, alors que le nœud n'a rien envoyé.
- Le journal du serveur indique `auth=token` : **rien ne distingue l'attaquant du vrai nœud**.
- La connexion est pourtant en HTTPS. *TLS chiffre, mais ne prouve pas qui est le client.*

## 4. Scénario B : mTLS

```bash
# A — Ctrl-C, puis serveur en mode sécurisé
make run-mtls
# B — le nœud présente son certificat
python3 /opt/iiot/client/edge_mtls.py --server https://api.iiot.lab:8443
openssl x509 -in /etc/iiot/pki/edge-01.crt -noout -subject -issuer -ext subjectAltName,extendedKeyUsage
# C — quatre tentatives d'intrusion, Entrée entre chacune
make attack-mtls
```

| # | Tentative | Résultat attendu | Ce que ça démontre |
|---|---|---|---|
| 1 | Aucun certificat | `tlsv13 alert certificate required` | Le serveur exige l'identité **avant** toute requête HTTP |
| 2 | Token volé (valable en scénario A), sans certificat | même alerte | Le token n'est **jamais lu** |
| 3 | Certificat `CN=edge-01` signé par une **CA pirate** | `tlsv1 alert unknown ca` | Le nom ne prouve rien : c'est la **signature** d'une CA de confiance qui compte |
| 4 | Nœud légitime (`edge-02`) qui se fait passer pour `edge-01` | `HTTP 403` | L'identité vient **du certificat**, jamais du contenu du message |

Dans le journal du serveur, repérez : `handshake TLS refusé … aucune requête HTTP lue` (cas 1 à 3) et
`CN=edge-01 SAN=edge-01.iiot.lab,urn:iiot:device:edge-01 issuer=IIoT Lab Root CA` (nœud accepté).

**Questions pour vous**
1. À quelle couche du modèle OSI le rejet des cas 1 à 3 a-t-il lieu ? Qu'est-ce qui le prouve dans les journaux ?
2. Pourquoi le cas 3 échoue-t-il alors que le CN est identique à celui du vrai nœud ?
3. Pourquoi le cas 4 passe-t-il la couche TLS mais est-il quand même refusé ?

## 5. La limite : où est la clé privée ?

Le nœud lit `/etc/iiot/pki/edge-01.key` **sur sa carte SD**. Refaites le geste de l'attaquant : copiez ce fichier.
Avec le certificat et la clé, il est de nouveau accepté par le serveur, et `mtls` ne voit **aucune différence**.

Le mTLS déplace donc le problème sans le résoudre : l'identité vaut ce que vaut la protection de la clé privée.
Les pistes industrielles pour que la clé ne soit **jamais extractible** : *Secure Element* (ex. ATECC608), **TPM 2.0**,
enclave **ARM TrustZone**, et un enrôlement sans intervention humaine (*zero-touch provisioning*, EST/ACME pour renouveler,
CRL/OCSP pour révoquer). La révocation n'est pas implémentée dans cette démo.

## Pour aller plus loin

- Capturer le trafic pendant l'attaque 1 : `sudo tcpdump -i any -n port 8443` (ou Wireshark). Où voit-on le rejet ?
- Mettre l'horloge du nœud en 2020 (`sudo date -s 2020-01-01`, après `sudo systemctl stop chrony`) : que devient le handshake ?
- Inspecter une chaîne : `openssl verify -CAfile pki/out/ca/ca.crt pki/out/rogue/edge-01.crt`.
- Réduire la durée de vie des certificats (`DAYS_LEAF` dans `pki/make_pki.sh`) et observer l'expiration.
- Ajouter une liste d'appareils autorisés dans `server/app.py` (un certificat valide n'est pas forcément *enrôlé*).

## Dépannage

| Symptôme | Cause probable |
|---|---|
| `certificate is not yet valid` / `has expired` | Horloge du nœud fausse : `chronyc tracking`, `date` |
| `Name or service not known: api.iiot.lab` | Entrée `/etc/hosts` manquante : relancer `provision.sh` avec `SERVER_IP` |
| `hostname mismatch` | Le nom utilisé n'est pas dans le SAN du certificat serveur : régénérer avec `SERVER_IP=…` |
| `Connection refused` / timeout | Serveur arrêté, mauvais port, ou pare-feu (8000/8443) : pare-feu ouvert (sous Fedora : `server/setup_fedora.sh`), puis `server/preflight.sh` |
| Le nœud est injoignable ou l'heure dérive | Mauvaise IP détectée (Wi-Fi au lieu du câble) : préciser `SERVER_IP=` |
| `curl` passe par un proxy et échoue | Variables `https_proxy` : les scripts utilisent déjà `--noproxy '*'` |
| `No such file … edge-01.key` | Oublié `make push-creds` |

## Arborescence

```
pki/make_pki.sh        Mini-PKI OpenSSL : CA, serveur, clients, CA pirate (EC P-256)
server/app.py          API FastAPI (/telemetry, /health), identité (token ou CN/SAN), dashboard
server/run.py          Lancement Uvicorn, lecture du certificat client, alertes TLS, journaux
server/dashboard.html  Supervision (courbes, seuil critique, alarme)
client/                Clients du nœud : edge_token.py (vulnérable), edge_mtls.py (sécurisé), bibliothèque standard seule
attacker/              replay_token.py (token volé) · mtls_attacks.sh (4 intrusions rejouables)
pi/provision.sh        Préparation du nœud Edge (hostname, NTP, hosts, /etc/iiot)
server/setup_fedora.sh Préparation du serveur, version Fedora (dnf, firewalld, chrony)
server/preflight.sh    Contrôles avant la démo : serveur et nœud Edge (heure, certificats, ports)
docs/DEMO_REPRODUCTION.md    Guide pour reproduire la démo chez soi, de zéro
tests/e2e.sh           Test de bout en bout (`make test`)
```

## Pour les curieux : deux détails d'implémentation

- **Lire le CN/SAN dans FastAPI.** Uvicorn ne transmet pas le certificat client à l'application. `server/run.py` sous-classe le
  protocole HTTP pour lire `ssl_object.getpeercert()` une fois la poignée de main validée, et l'ajoute au contexte de chaque requête.
- **Rendre le rejet visible.** Par défaut, asyncio coupe la connexion sans envoyer l'alerte TLS : le client voit « connection reset ».
  `install_tls_reject_hook()` envoie l'alerte avant de couper, et journalise le motif. Il s'appuie sur des méthodes internes d'asyncio
  (testé avec Python 3.13 et 3.14) : si elles changent, le hook se désactive et `make test` le signale.

## Tests et avertissement

`make test` génère une PKI jetable, lance les deux serveurs sur des ports de test et vérifie 20 comportements attendus (dont ce que le dashboard enregistre)
(token volé accepté, rejets TLS, usurpation refusée, journaux). Les secrets générés ne servent qu'à cette démo :
**ne réutilisez jamais ces clés, tokens ou cette CA ailleurs.**
