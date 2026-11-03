# CLAUDE.md · Neckr0ik/Neckr0ik

Repo de perfil/portafolio de GitHub de Giovanni Oliveira (Impulse Labs, "Digital Forge"). Mezcla documentación pública
(Markdown) con paquetes Python de código abierto en `open-lab/`. El `README.md` raíz es el perfil que GitHub muestra.

## Estructura
- `README.md`: perfil (Hybrid Intelligence, Open Lab, Founder Track). En inglés, con resúmenes en ES/PT.
- `0-Profile/`: `skills-matrix.csv` (habilidad → proyecto).
- `1-Cybersecurity/`: Network Defense (`packet-sniffer-scapy` con tests, consultas Wazuh, análisis tcpdump),
  System Hardening (auditoría Botium Toys, laboratorio Vagrant, `harden.sh` STIG/CIS), Incident Response
  (playbooks, casos, `remediation-bot-slack/bot.py`).
- `2-Cloud-Engineering/`: Terraform `azure-secure-blueprint` (`main.tf`, `variables.tf`).
- `3-Data-Analytics/`: `sql-defence-playground` (`app.py`), `auth-log-parser`, `nmap-bulk-scanner-reporter`.
- `4-Psychology/`: factores humanos (phishing, awareness training). `5-Business-Admin/`: políticas y risk assessment.
- `docs/`: ética, contribución, seguridad, código de conducta (multilingüe). `hybrid-intelligence/`: método y build log.
- `open-lab/`: paquetes independientes (cada uno con su `pyproject.toml`, README, LICENSE MIT y tests), Python >= 3.11:
  - `mx-census-sampler` (CLI `mx-census-sampler`): muestreo PPS de municipios con Censo 2020 (numpy, pandas).
  - `endutih-media-profiles` (CLIs `endutih-profiles`, `endutih-profiles-prepare`): uso de medios ENDUTIH 2025.
  - `llm-survey-bias-kit` (CLI `llm-bias-kit`): sesgo de orden, A/B pareado, A/A, homogeneidad (numpy).
  - `silicon-sample-validation` (CLI `ssv`): registro de pronósticos con hash, guardas de cutoff, baselines; extra `anthropic`.
  - `llm-gateway-metering` (CLI `llm-gateway`): pasarela Anthropic API / Bedrock / Vertex con cuotas y metering;
    núcleo solo stdlib, extras `anthropic`, `bedrock`, `vertex`, `postgres`; stores SQLite/Postgres.
  - `graphiti-mcp`: infraestructura (no es paquete Python, no está en CI). Ver abajo.
  - `firecrawl-mcp`: infraestructura, mismo patrón que `graphiti-mcp`. Ver abajo.

## Comandos (verificados en `.github/workflows/open-lab.yml` y `open-lab/README.md`)
```bash
# Tests de un paquete de open-lab (igual que CI)
cd open-lab/<paquete>
python -m pip install --upgrade pip
pip install -e . pytest
if [ -f requirements-dev.txt ]; then pip install -r requirements-dev.txt; fi
pytest -q

# Ejemplo de CLI
mx-census-sampler sample -n 400 --seed 2027

# Tests del sniffer
cd 1-Cybersecurity/1.1-Network-Defense/packet-sniffer-scapy
pip install scapy pytest
pytest -q test_sniffer.py
```
CI (`open-lab tests`): push a `main` y PRs; matriz de los 5 paquetes x Python 3.11 y 3.12, más el job `packet-sniffer`
(Python 3.12). Algunos tests necesitan el SDK opcional de Anthropic o una key real y no corren offline.

## open-lab/graphiti-mcp (memoria Graphiti autoalojada)
- `docker-compose.yml`: `zepai/knowledge-graph-mcp` (Graphiti + FalkorDB en el mismo contenedor), `caddy` (solo responde
  bajo `/<MCP_SECRET_PATH>/`, lo demás 404) y una salida pública por perfil: `tailscale` (Funnel, recomendado) o
  `tunnel` (Cloudflare). Puertos 8000 (MCP) y 3000 (FalkorDB Browser) solo en `127.0.0.1`.
- `config/config.yaml`: LLM Gemini (`gemini-3-flash-preview`, env `LLM_PROVIDER`/`LLM_MODEL`), embeddings/reranker Gemini
  (`gemini-embedding-001`, 768 dim). No usar Anthropic: graphiti-core le envía `temperature` y la API lo rechaza;
  base FalkorDB (`default_db`).
- `windows/`: `1-instalar-graphiti.ps1` (crea `.env`, levanta todo, muestra la URL), `2-configurar-pc-servidor.ps1`
  (Admin: autologin, sin suspensión, tareas programadas), `healthcheck.ps1` (cada 5 min).
- Arranque: `docker compose --profile tailscale up -d` (o `--profile tunnel`). Logs: `docker compose logs -f graphiti`.
- `.env` está en `.gitignore`: nunca lo subas ni copies sus valores. La ruta secreta es la única llave del grafo.
- Según su README, los `.ps1` no se han probado en Windows y el contenedor de Tailscale no se ha arrancado con key real.

## open-lab/firecrawl-mcp (scraping autoalojado)
- `docker-compose.yml`: `firecrawl-mcp` (imagen propia del `Dockerfile`, versión npm fijada, modo HTTP en `127.0.0.1:3010/mcp`),
  `caddy` (ruta secreta; reescribe `Host` a localhost y quita `Origin`, porque firecrawl-mcp da 403 si no) y `tailscale`
  (Funnel, sin perfil: siempre activo).
- Necesita el Firecrawl self-hosted (`$HOME\firecrawl`, repo upstream sin cambios) levantado antes: el MCP usa su red externa
  `firecrawl_backend` (`http://api:3002`). `firecrawl/` guarda el `.env` y el `docker-compose.override.yaml` que se copian ahí
  (restart automático y puerto 3002 solo en `127.0.0.1`).
- `windows/1-instalar-firecrawl.ps1`: idempotente; instala Firecrawl, genera `MCP_SECRET_PATH`, pide `TS_AUTHKEY` oculta y
  muestra la URL. En PS 5.1 los comandos nativos van por `Invoke-Native` (stderr + `Stop` rompe el script).
- `.env` en `.gitignore`. No reutilizar valores del `.env` de `graphiti-mcp`.

## Convenciones
- Commits estilo Conventional Commits (`feat(open-lab): ...`, `fix(graphiti-mcp): ...`, `docs: ...`, `chore: ...`).
- Trabajo por ramas `claude/*` y PR a `main`.
- Contenido público: nada de datos de clientes, entrevistas ni internals de productos (solo datos públicos de INEGI).
- Las cifras de tests del README (por paquete y total) deben actualizarse si cambian los tests.
- No subir artefactos de sesiones de IA, bytecode ni logs (`.gitignore`).

## Gotchas
- `requirements.txt` raíz es una lista amplia y no la usa CI; cada paquete declara sus deps en `pyproject.toml`.
- `graphiti-mcp` no tiene tests en CI; valida cambios con `docker compose config`.

## Memoria persistente (Graphiti MCP)
Este proyecto usa el connector **Graphiti** (memoria en grafo compartida entre sesiones).
- `group_id` de este repo: `neckr0ik`. Datos del usuario y transversales: `neckr0ik-global`.
- Al empezar una tarea: busca contexto con `search_memory_facts` y `search_nodes` usando `group_ids: ["neckr0ik", "neckr0ik-global"]`.
- Al terminar algo relevante (decisión de arquitectura, convención nueva, bug resuelto y su causa, preferencia del usuario, estado de un despliegue): guárdalo con `add_memory` (`group_id: "neckr0ik"`, `source: "text"`) con un nombre descriptivo.
- Nunca guardes secretos, API keys, tokens, contraseñas ni datos personales sensibles.
- Si Graphiti no está disponible en la sesión, continúa normalmente.
