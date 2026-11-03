# Raccourcis de démo.  `make help` liste les cibles.
PY      ?= .venv/bin/python
PI      ?= noah@10.42.0.167
DEV     ?= edge-01
# Adresse du serveur vue par le Pi / l'attaquant (doit résoudre vers le portable)
SERVER  ?= api.iiot.lab

.DEFAULT_GOAL := help
.PHONY: help venv pki tokens run-token run-mtls attack-token attack-mtls test push-code push-creds clean

help: ## Affiche cette aide
	@grep -E '^[a-z-]+:.*##' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  \033[96m%-13s\033[0m %s\n", $$1, $$2}'

venv: ## Crée le virtualenv et installe les dépendances
	python3 -m venv .venv && .venv/bin/pip install -q -r requirements.txt

pki: ## (Re)génère PKI + tokens (CA, serveur, clients, CA pirate) 
	bash ./pki/make_pki.sh --force
	python3 server/gen_tokens.py

tokens: ## Régénère seulement les tokens statiques (scénario vulnérable)
	python3 server/gen_tokens.py

run-token: ## Serveur VULNÉRABLE : TLS simple + token statique (port 8000)
	$(PY) -m server.run --mode token

run-mtls: ## Serveur SÉCURISÉ : TLS mutuel (port 8443)
	$(PY) -m server.run --mode mtls

attack-token: ## Attaquant : d'abord sans token (401), puis avec le token volé (11,5 bar)
	$(PY) attacker/replay_token.py --server https://$(SERVER):8000 --ca pki/out/ca/ca.crt \
	      --token-file pki/out/tokens/$(DEV).token --device-id $(DEV) --value 11.5

attack-mtls: ## Attaquant : 4 tentatives contre l'API mTLS, avec pause entre chaque
	SERVER=https://$(SERVER):8443 bash ./attacker/mtls_attacks.sh --pause

test: ## Test de bout en bout local (PKI + 2 serveurs + attaques)
	PY=$(PY) bash ./tests/e2e.sh

push-code: ## Copie client/ et pi/ sur le Pi (~/iiot)
	ssh $(PI) 'mkdir -p ~/iiot'
	scp -r client pi $(PI):~/iiot/

push-creds: ## Copie CA + certificat/clé + token de $(DEV) sur le Pi (/etc/iiot, après provision.sh)
	scp pki/out/ca/ca.crt pki/out/devices/$(DEV)/$(DEV).crt pki/out/devices/$(DEV)/$(DEV).key $(PI):/etc/iiot/pki/
	scp pki/out/tokens/$(DEV).token $(PI):/etc/iiot/token

clean: ## Supprime les secrets générés
	rm -rf pki/out server/tokens.json
