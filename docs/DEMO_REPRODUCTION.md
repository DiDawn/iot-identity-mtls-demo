# Reproduire la démonstration : du token statique au mTLS

Ce guide s'adresse à **quelqu'un qui récupère ce dépôt et veut rejouer la démonstration chez lui**, sans connaître la configuration de l'auteur.
Il part de zéro : matériel, réseau, installation, vérifications, puis déroulé des deux scénarios.

**Dépôt** : <https://github.com/DiDawn/iot-identity-mtls-demo>

> **Compatibilité : testé sous Fedora.** La démonstration a été mise au point et vérifiée de bout en bout (serveur + Raspberry Pi 3B) avec un **serveur Fedora**.
> Les parties qui n'en dépendent pas (PKI OpenSSL, serveur FastAPI, clients, attaques, dashboard, `make test`) sont du Python et de l'OpenSSL standard :
> `make test` a aussi été exécuté sur Ubuntu 24.04 avec Python 3.14. En revanche, **je ne peux pas garantir que le reste (réseau, pare-feu, serveur de temps)
> soit parfaitement reproductible sur une autre distribution**. Les étapes spécifiques à Fedora sont signalées par la mention **[Fedora]** ; pour une autre distribution,
> voir le §10 (équivalents proposés, non testés sur le matériel).

**Durée** : environ 45 minutes la première fois (dont 10 pour installer le Raspberry Pi), 5 minutes ensuite.
**Résultat** : vous volez l'identité d'un capteur avec un simple `cat`, puis vous voyez le serveur rejeter le même attaquant dès la poignée de main TLS.

---

## 1. Ce qu'il vous faut

| Rôle | Matériel | Logiciel |
|---|---|---|
| **Serveur IoT** (+ attaquant + navigateur) | Un serveur ou PC **Linux**. Testé sous Fedora ; autres distributions : voir §10 | `python3` (3.13 ou 3.14), `openssl`, `curl`, `make`, `ssh` |
| **Nœud Edge** | Un Raspberry Pi (testé sur un Pi 3B) avec carte SD | Raspberry Pi OS Lite 64 bits (Debian 13) |
| **Liaison** | Un câble Ethernet entre le PC et le Pi, ou un réseau commun (box, switch) | |

**Pas de Raspberry Pi ?** La démonstration fonctionne aussi sur **une seule machine** : voir §9. Vous perdez seulement la dimension « objet physique » et l'histoire de l'horloge.

Les droits `sudo` sont nécessaires sur le PC (paquets, pare-feu, `/etc/hosts`, serveur de temps) et sur le Pi (provisioning).

> **Important : les valeurs par défaut du dépôt sont celles de l'auteur.** Les scripts supposent un portable en `10.42.0.1` et un Pi accessible par `noah@10.42.0.167`.
> Vous allez devoir les remplacer par les vôtres : c'est l'objet de l'étape 3, à ne pas sauter.

---

## 2. Comprendre ce que vous allez construire

```
   Nœud Edge (Raspberry Pi)                   Serveur IoT (votre PC)
   ┌──────────────────────┐   HTTPS (8000)    ┌─────────────────────────────┐
   │ /etc/iiot/token      │ ───────────────▶  │ Scénario A : token statique │
   │ /etc/iiot/pki/*.crt  │   mTLS  (8443)    │ Scénario B : mTLS (CA privée)│──▶ Dashboard
   │ /etc/iiot/pki/*.key  │ ───────────────▶  │ FastAPI + Uvicorn           │   http://127.0.0.1:8080
   └──────────────────────┘                   └─────────────────────────────┘
                                                        ▲
                                           Attaquant (un autre terminal du PC)
```

- **Scénario A, vulnérable** (port 8000) : TLS simple, le nœud s'identifie par un token statique. L'attaquant le copie et injecte de fausses mesures.
- **Scénario B, sécurisé** (port 8443) : TLS mutuel. Le nœud prouve son identité avec un certificat X.509 signé par une CA privée. L'attaquant est rejeté avant d'avoir envoyé la moindre requête HTTP.

Le dépôt contient tout : une mini-PKI OpenSSL (`pki/`), le serveur (`server/`), les clients du nœud (`client/`), les attaques (`attacker/`), la préparation du Pi (`pi/`).

---

## 3. Choisir vos adresses (à faire une fois)

Vous avez besoin de deux informations :

| Variable | Signification | Exemple |
|---|---|---|
| `SERVER_IP` | L'adresse du **PC**, **telle que le Pi la voit** | `10.42.0.1` |
| `PI` | Compte SSH et adresse du **Pi** | `pi@10.42.0.50` |

### Option B : câble Ethernet direct (recommandé : indépendant du réseau de la salle)

Le PC joue le routeur DHCP du Pi, avec **NetworkManager** (`nmcli`, présent par défaut sous Fedora et sur beaucoup de distributions de bureau ; sans lui, configurez un serveur DHCP à la main ou utilisez l'option A). Repérez l'interface Ethernet avec `nmcli device`, puis :

```bash
nmcli con add type ethernet ifname <interface-ethernet> con-name iiot-lab ipv4.method shared ipv4.addresses 10.42.0.1/24
nmcli con up iiot-lab
```

Dans ce cas `SERVER_IP=10.42.0.1` : c'est la valeur par défaut des scripts, vous n'avez rien à changer de ce côté.
Le Wi-Fi du PC reste utilisable pour Internet.

### Option A : le PC et le Pi sont sur le même réseau

`SERVER_IP` est l'adresse du PC sur ce réseau (`ip -4 -br addr`). Attention : certains réseaux (Wi-Fi public, entreprise) **isolent les machines entre elles** ; si le Pi ne joint pas le PC, utilisez l'option B.

### Trouver l'adresse du Pi

Branchez le Pi (démarrage : environ 40 s), puis sur le PC :

```bash
sudo journalctl -u NetworkManager --since "10 min ago" | grep DHCPACK    # option B : ligne « DHCPACK(...) 10.42.0.x <MAC> <nom> »
ip neigh                                                                  # autre méthode : MAC en b8:27:eb, dc:a6:32, e4:5f:01 ou d8:3a:dd
```

Si rien n'apparaît : `ip -br link` (`NO-CARRIER` = câble non détecté) et `nmcli -f NAME,DEVICE,STATE con show --active`.

### Enregistrer vos valeurs

Dans **chaque terminal** que vous utiliserez sur le PC (ou dans votre `~/.bashrc`) :

```bash
export SERVER_IP=10.42.0.1        # l'adresse du PC vue par le Pi
export PI=pi@10.42.0.50           # utilisateur@adresse du Pi
```

Le Makefile et les scripts lisent ces variables : vous n'avez rien d'autre à modifier dans le dépôt.

---

## 4. Préparer le PC (serveur IoT)

```bash
git clone https://github.com/DiDawn/iot-identity-mtls-demo.git
cd iot-identity-mtls-demo
chmod +x server/*.sh pki/*.sh pi/*.sh attacker/*.sh tests/*.sh     # utile si l'archive a perdu les droits d'exécution
```

**[Fedora]** Le script de préparation est écrit pour Fedora (`dnf`, `firewalld`) :

```bash
bash server/setup_fedora.sh
```

**Autre distribution Linux** : ce script ne s'y applique pas, faites les équivalents du §10, puis revenez ici.

Le script Fedora, relançable à volonté :
- installe les paquets manquants (`python3`, `openssl`, `curl`, `make`, `chrony`, `openssh-clients`) ;
- crée `.venv` et installe FastAPI/Uvicorn ;
- ajoute `api.iiot.lab` à `/etc/hosts` (pour le terminal de l'attaquant) ;
- ouvre `8000/tcp`, `8443/tcp` et `123/udp` dans firewalld, **de façon temporaire** (à refaire après un redémarrage ; `PERMANENT=1` pour garder) ;
- transforme `chronyd` en serveur de temps pour le Pi, qui n'a pas d'horloge matérielle.

Il s'arrête avec « Aucune interface ne porte … » si le lien vers le Pi n'est pas actif : branchez le câble et lancez `nmcli con up iiot-lab`.

Vérifiez que le serveur fonctionne **avant** d'y mêler le Pi :

```bash
make test        # 20 vérifications, doit finir par « Tous les tests passent. »
```

---

## 5. Générer l'identité : la mini-PKI

```bash
make pki
```

Cela crée dans `pki/out/` (jamais versionné) :

| Élément | Rôle |
|---|---|
| CA privée « IIoT Lab Root CA » | Signe les certificats. C'est elle seule qui décide qui entre |
| Certificat serveur `api.iiot.lab` (SAN : nom + `SERVER_IP`) | Prouve l'identité du serveur au nœud |
| Certificats clients `edge-01`, `edge-02` | Identités des nœuds (CN, SAN, usage `clientAuth`) |
| **CA pirate** + certificat `CN=edge-01` | Pour l'attaque n° 3 : même nom, mauvaise signature |
| Tokens statiques `edge-01`, `edge-02` | Pour le scénario vulnérable |

Si vous changez d'adresse ou de réseau plus tard, relancez `make pki` (puis `make push-creds`) : le SAN du serveur contient l'adresse.

---

## 6. Préparer le Raspberry Pi

### 6.1 Installer le système

Avec Raspberry Pi Imager : **Raspberry Pi OS Lite (64-bit)**. Dans les réglages avancés, définissez un utilisateur, **activez SSH**, et laissez le réseau filaire en DHCP. Notez le nom d'utilisateur : c'est celui de `PI`.

### 6.2 Provisionner depuis le PC

```bash
make push-code                                    # copie client/ et pi/ dans ~/iiot du Pi
ssh -t "$PI" "sudo SERVER_IP=$SERVER_IP bash ~/iiot/pi/provision.sh"
make push-creds                                   # CA, certificat, clé et token de edge-01 vers /etc/iiot
```

SSH demandera le mot de passe du Pi à chaque connexion ; pour ne le saisir qu'une fois : `ssh-copy-id "$PI"`.

`provision.sh` (idempotent) règle le nom d'hôte (`edge-01`), le fuseau, `chrony` (heure prise sur votre PC), l'entrée `api.iiot.lab → SERVER_IP` dans `/etc/hosts`, et crée `/etc/iiot/` et `/opt/iiot/client`.

> **Le piège de l'horloge.** Un Raspberry Pi 3 n'a pas de pile. S'il démarre sans réseau NTP, sa date est fausse et il **rejette les certificats** (« not yet valid »). C'est pourquoi le PC sert l'heure au Pi.

### 6.3 Tout contrôler d'un coup

```bash
bash server/preflight.sh
```

Le script vérifie l'environnement Python, la PKI, les ports libres, `chrony`, puis se connecte au Pi : heure à 5 s près, certificat valide et signé par la CA, résolution de `api.iiot.lab`, synchronisation NTP, et accès réel du Pi aux ports 8000 et 8443 (test du pare-feu). Il se termine par **« Tout est prêt »** ; sinon il liste ce qu'il reste à corriger. Ne continuez pas tant qu'il n'est pas vert.

---

## 7. Jouer la démonstration

Ouvrez **trois terminaux** et un navigateur sur **http://127.0.0.1:8080**.

| Terminal | Rôle | Où |
|---|---|---|
| **A** | Serveur IoT | PC |
| **B** | Nœud Edge | SSH sur le Pi (`ssh "$PI"`) |
| **C** | Attaquant | PC |

N'oubliez pas les `export SERVER_IP=… PI=…` dans les terminaux du PC.

### Scénario A : l'identité vole en éclats

```bash
# A  : serveur vulnérable (TLS simple + token)
make run-token

# B  : le nœud envoie sa pression (≈ 4,2 bar)
python3 /opt/iiot/client/edge_token.py --server https://api.iiot.lab:8000

# B (2e onglet SSH) : « on retire la carte SD » : le secret est lisible
cat /etc/iiot/token

# C  : l'attaquant, en deux phases (Entrée entre les deux)
make attack-token
```

**Ce que vous devez observer**
1. **Phase 1, sans token** : 4 paquets, 4 réponses `HTTP 401 token manquant`. Sur le dashboard, des ✕ orange dans le couloir « rejets ».
2. **Phase 2, avec le token volé** : `HTTP 201`. La courbe monte à **11,5 bar**, la carte passe en **alarme rouge**, alors que le nœud n'a rien envoyé.
3. Dans le journal du serveur, `auth=token` : **rien ne distingue l'attaquant du vrai nœud**.
4. La connexion était pourtant en HTTPS : *TLS chiffre le canal et prouve l'identité du serveur, pas celle du client.*

### Scénario B : le même vol, sans effet

```bash
# A  : Ctrl-C, puis serveur sécurisé (TLS mutuel, port 8443)
make run-mtls

# B  : le nœud présente son certificat
python3 /opt/iiot/client/edge_mtls.py --server https://api.iiot.lab:8443
openssl x509 -in /etc/iiot/pki/edge-01.crt -noout -subject -issuer -ext subjectAltName,extendedKeyUsage

# C  : quatre intrusions, Entrée entre chacune
make attack-mtls
```

| # | Tentative | Résultat attendu | Ce que cela démontre |
|---|---|---|---|
| 1 | Aucun certificat | `tlsv13 alert certificate required` | Le serveur exige l'identité **avant** toute requête HTTP |
| 2 | Token volé (valable en A), sans certificat | même alerte | Le token n'est **jamais lu** |
| 3 | `CN=edge-01` signé par la **CA pirate** | `alert unknown ca` | Le nom ne prouve rien : seule compte la **signature** d'une CA de confiance |
| 4 | Un nœud légitime (`edge-02`) se fait passer pour `edge-01` | `HTTP 403` | L'identité vient **du certificat**, jamais du contenu du message |

Dans le journal du serveur : `handshake TLS refusé … aucune requête HTTP lue` pour les cas 1 à 3, et
`CN=edge-01 SAN=edge-01.iiot.lab,urn:iiot:device:edge-01 issuer=IIoT Lab Root CA` pour le nœud accepté.
Le cas 4 passe la couche TLS (le certificat d'`edge-02` est valide) et se fait refuser par l'API : deux niveaux, **authentification** puis **autorisation**.

### Le dashboard

- **⏸ / ▶ en haut à gauche** (ou **Espace**) fige l'affichage pour commenter ; les données continuent d'arriver.
- **Survolez un point** de la courbe, ou un ✕ du couloir « rejets » : le contenu du paquet s'affiche (source, chiffrement, token masqué ou certificat, corps JSON, motif du rejet). Un clic garde l'infobulle ouverte.
- **Bouton rond en haut à droite** (ou touche **T**) : thèmes `papier`, `clair`, `contraste`, `sombre` ; `?theme=clair` dans l'URL pour en imposer un.
- Un cercle blanc signale une **source inhabituelle** (autre adresse IP que celle qui envoie d'habitude) ; c'est une aide de lecture, le serveur ne s'en sert pas.

### La limite à ne pas rater : où est la clé privée ?

Sur le Pi, la clé est un fichier : `/etc/iiot/pki/edge-01.key`. Copiez-la avec le certificat sur le PC et rejouez la connexion : le serveur l'accepte, `mtls` ne voit **aucune différence**.

Le mTLS déplace le problème, il ne le supprime pas : **l'identité vaut la protection de sa clé privée**. Pistes industrielles : *Secure Element* (ex. ATECC608), **TPM 2.0**, enclave **ARM TrustZone**, enrôlement sans intervention (*zero-touch provisioning*, EST/ACME), révocation (CRL, OCSP). La révocation n'est pas implémentée dans cette démo.

---

## 8. Si quelque chose ne marche pas

| Symptôme | Cause probable | Que faire |
|---|---|---|
| **[Fedora]** `setup_fedora.sh` : « Aucune interface ne porte … » | Le lien vers le Pi n'est pas actif, ou `SERVER_IP` n'est pas l'adresse de votre PC | `nmcli con up iiot-lab`, ou `ip -4 -br addr` puis `export SERVER_IP=…` |
| `preflight.sh` : « connexion SSH impossible » | `PI` mal renseigné ou Pi pas encore démarré | `echo $PI`, `ping <adresse>`, attendre 40 s |
| Le Pi n'atteint pas 8000/8443 | Pare-feu du PC : règles effacées au redémarrage, ou ports ouverts dans la mauvaise zone | **[Fedora]** `bash server/setup_fedora.sh` (ou `PERMANENT=1 …`) ; autre distribution : ouvrir 8000/tcp, 8443/tcp, 123/udp dans votre pare-feu |
| `certificate is not yet valid` / `has expired` | Horloge du Pi fausse | Sur le Pi : `chronyc tracking`, `date` ; relancer `provision.sh` avec `SERVER_IP` |
| `hostname mismatch` | Le nom ou l'adresse utilisés ne sont pas dans le SAN du serveur | `make pki` avec la bonne `SERVER_IP`, puis `make push-creds` |
| `Name or service not known: api.iiot.lab` | Entrée `/etc/hosts` manquante | PC : ajouter `127.0.0.1 api.iiot.lab` à `/etc/hosts` (**[Fedora]** : `setup_fedora.sh` le fait) ; Pi : relancer `provision.sh` |
| `Address already in use` | Un ancien serveur tourne encore | `ss -ltnp \| grep -E '8000\|8443\|8080'` puis l'arrêter |
| `No such file … edge-01.key` sur le Pi | `make push-creds` oublié | Le relancer |
| `make test` échoue sur un test TLS avec une autre version de Python | Le crochet qui rend les alertes TLS visibles utilise des méthodes internes d'asyncio | Utiliser Python 3.13 ou 3.14, ou signaler le message |
| `curl` passe par un proxy | Variables `https_proxy` | Les scripts du dépôt utilisent déjà `--noproxy '*'` |

---

## 9. Variante sans Raspberry Pi (une seule machine)

Le serveur, le nœud et l'attaquant tournent sur le même PC. Le déroulé est identique ; l'attaquant a la même adresse source que le nœud (le cercle « source inhabituelle » n'apparaîtra pas).

```bash
export SERVER_IP=127.0.0.1
make venv
echo "127.0.0.1 api.iiot.lab" | sudo tee -a /etc/hosts
make pki
make test
```

Puis les mêmes trois terminaux, mais le nœud lit ses secrets dans le dépôt au lieu de `/etc/iiot` :

```bash
# A
make run-token                    # puis, pour le scénario B : make run-mtls

# B : scénario A
python3 client/edge_token.py --server https://api.iiot.lab:8000 \
        --ca pki/out/ca/ca.crt --token-file pki/out/tokens/edge-01.token
cat pki/out/tokens/edge-01.token  # « le secret est lisible »

# B : scénario B
python3 client/edge_mtls.py --server https://api.iiot.lab:8443 --ca pki/out/ca/ca.crt \
        --cert pki/out/devices/edge-01/edge-01.crt --key pki/out/devices/edge-01/edge-01.key

# C : identique
make attack-token         # ou make attack-mtls
```

---

## 10. Serveur Linux autre que Fedora (non garanti)

`server/setup_fedora.sh` s'appuie sur `dnf` et `firewalld`, et `server/preflight.sh` sur `chronyd` et `firewalld`. Voici les équivalents pour Debian ou Ubuntu.
**Ils n'ont pas été éprouvés sur du matériel** : si une étape se comporte différemment chez vous (nom du service `chrony`, chemin de configuration, pare-feu), les symptômes sont ceux du §8.
Seul le **Pi** (Raspberry Pi OS / Debian) est de toute façon préparé par `pi/provision.sh`, quelle que soit la distribution du serveur.

Python : le dépôt est testé avec **3.13 et 3.14**. Sur une distribution qui fournit une version plus ancienne, installez une version récente (le crochet qui rend les alertes TLS visibles dépend d'éléments internes d'asyncio, voir §8).

```bash
sudo apt install python3 python3-venv openssl curl make openssh-client chrony
make venv
echo "127.0.0.1 api.iiot.lab" | sudo tee -a /etc/hosts
sudo ufw allow 8000/tcp; sudo ufw allow 8443/tcp; sudo ufw allow 123/udp      # seulement si ufw est actif
```

Pour l'heure du Pi, ajoutez dans la configuration de `chrony` (`/etc/chrony/conf.d/iiot.conf`) :
`allow <réseau du Pi, ex. 10.42.0.0/24>` et `local stratum 10`, puis `sudo systemctl restart chrony`.
Le reste (`make pki`, `push-code`, `provision.sh`, `push-creds`, scénarios) est identique. Dans `server/preflight.sh`, ignorez les avertissements sur `chronyd` et `firewalld` s'ils ne s'appliquent pas à votre système.

---

## 11. Tout remettre à zéro

```bash
make clean                            # supprime pki/out et server/tokens.json (secrets générés)
sudo sed -i '/api.iiot.lab/d' /etc/hosts
sudo rm -f /etc/chrony.d/iiot.conf && sudo systemctl restart chronyd   # [Fedora] ; Debian/Ubuntu : /etc/chrony/conf.d/iiot.conf et service chrony
sudo firewall-cmd --reload            # [Fedora] efface les règles temporaires ; ailleurs, retirez vos règles ufw
nmcli con delete iiot-lab             # si vous aviez créé la liaison directe
```

Sur le Pi : `sudo rm -rf /etc/iiot /opt/iiot ~/iiot`.

> **Ne réutilisez jamais** ces clés, tokens ou cette CA ailleurs : ils sont générés pour la démonstration et la clé de la CA n'est pas protégée.

---

## 12. Aller plus loin

- Capturer le trafic pendant l'attaque 1 : `sudo tcpdump -i any -n port 8443` (ou Wireshark). Où voit-on le rejet ?
- Mettre l'horloge du nœud en 2020 (`sudo systemctl stop chrony && sudo date -s 2020-01-01`) : que devient la poignée de main ?
- Vérifier une chaîne : `openssl verify -CAfile pki/out/ca/ca.crt pki/out/rogue/edge-01.crt`.
- Raccourcir la durée de vie des certificats (`DAYS_LEAF` dans `pki/make_pki.sh`) et observer l'expiration.
- Ajouter dans `server/app.py` une liste de nœuds autorisés : un certificat valide n'est pas forcément *enrôlé*.
- Lire [`../README.md`](../README.md) pour le glossaire et les détails d'implémentation (lecture du CN/SAN dans FastAPI, alertes TLS visibles).
