# Graphiti MCP: memoria persistente para todos tus proyectos de Claude Code

Servidor [Graphiti MCP](https://github.com/getzep/graphiti/tree/main/mcp_server) en tu PC con Windows, publicado con
**Tailscale Funnel** (recomendado, sin dominio) o **Cloudflare Tunnel**, sin abrir puertos y protegido con una **ruta secreta**. Se añade una sola vez como connector en
claude.ai y queda disponible en todas tus sesiones de Claude Code en la nube.

```
Claude (nube) ──HTTPS──> Tailscale Funnel / Cloudflare ──> contenedor tailscale / cloudflared ──> Caddy (ruta secreta) ──> Graphiti + FalkorDB
```

- **LLM:** Gemini (`gemini-3-flash-preview`, cambiable con `LLM_MODEL`). El cliente Anthropic de graphiti-core envía
  `temperature`, que el SDK/API actual de Anthropic rechaza, y cada episodio fallaba; por eso no se usa Anthropic.
- **Modelo small y reranker:** `gemini-3.5-flash-lite`. graphiti-core los fija en `gemini-2.5-flash-lite` (retirado por
  Google) sin opción de cambiarlo; `patches/graphiti_gemini_patch.py` los sustituye al arrancar (variables
  `GEMINI_SMALL_MODEL`, `GEMINI_RERANKER_MODEL`). Si cambias la imagen, revisa que la ruta `python3.13` siga igual.
- **Embeddings y reranker:** Gemini (`gemini-embedding-001`, 768 dimensiones). Con Gemini
  se evita la descarga de ~2.3 GB del reranker local.
- **Base de datos:** FalkorDB, dentro del mismo contenedor y con los datos en un volumen de Docker.

## Antes de empezar

1. **API key de Google** (aistudio.google.com). Si superas la capa gratis, activa facturación y pon un límite de gasto.
2. **Salida pública: elige una.**
   - **Tailscale (recomendado, gratis y sin dominio).** Tailscale corre como contenedor dentro de Docker (no hace falta
     instalarlo en Windows). En https://login.tailscale.com/admin:
     1. *DNS* → activa **MagicDNS** y **HTTPS Certificates**.
     2. *Access controls*: permite Funnel. Añade a la política `"nodeAttrs": [{"target": ["autogroup:member"], "attr": ["funnel"]}]`
        (el panel suele ofrecer un botón para hacerlo).
     3. *Settings → Keys* → *Generate auth key*: Reusable y **no** Ephemeral. Copia la key (`tskey-auth-...`).

     El resultado es una URL tipo `https://graphiti.<tu-tailnet>.ts.net/<secreto>/mcp`. Funnel la hace pública, que es
     necesario porque los connectors de claude.ai se conectan desde los servidores de Anthropic, que no están en tu
     tailnet. Tus otros dispositivos con Tailscale también pueden usarla.
   - **Cloudflare Tunnel (necesita un dominio en Cloudflare).** Ve a Zero Trust → Networks → Tunnels → *Create* →
     *Docker* y copia el token. En *Public hostname* apunta `graphiti.tu-dominio.com` → `HTTP` → `caddy:80`.

## Instalación (en el PC servidor)

```powershell
git clone https://github.com/Neckr0ik/Neckr0ik.git
cd Neckr0ik\open-lab\graphiti-mcp
powershell -ExecutionPolicy Bypass -File .\windows\1-instalar-graphiti.ps1
```

El script instala Docker Desktop si no lo tienes, te pregunta `tailscale` o `tunnel`, te pide las keys, genera la ruta
secreta, levanta todo y muestra la URL del connector (con Tailscale la detecta sola).

Después, en una **PowerShell como Administrador**:

```powershell
powershell -ExecutionPolicy Bypass -File .\windows\2-configurar-pc-servidor.ps1
```

Ese script hace lo siguiente:

| Qué | Cómo |
|---|---|
| Autologin | Sysinternals **Autologon**: tú escribes la contraseña en su ventana y queda cifrada (no en texto plano) |
| Nunca suspender | `powercfg`: sin suspensión ni hibernación, y la tapa cerrada no hace nada |
| Wi-Fi siempre conectada | Perfil en conexión automática y sin ahorro de energía en el adaptador |
| Sin reinicios por sorpresa | Windows Update no reinicia mientras haya una sesión iniciada |
| Arranque de programas | Tarea programada que abre Docker Desktop al iniciar sesión; los contenedores usan `restart: unless-stopped` |
| Health check | Tarea cada 5 min (`windows/healthcheck.ps1`), con registro en `windows/healthcheck.log` |

### Qué repara el health check, en orden
1. **Internet caído:** reconecta la Wi-Fi conocida y, si no basta, reinicia el adaptador.
2. **Docker caído:** arranca Docker Desktop.
3. **Graphiti caído:** `docker compose up -d` y, si sigue caído, `restart`.
4. **Salida pública caída** (si defines `PUBLIC_HEALTH_URL`): reinicia el contenedor `tailscale` o `cloudflared`.
5. **Aviso externo** (si defines `HEALTHCHECKS_PING_URL`, gratis en healthchecks.io): si el PC se apaga, se va la luz o
   pierde internet, te llega un email. Esto el propio PC no lo puede avisar, por eso hace falta el monitor externo.

## Conectarlo a Claude

- **Todas las sesiones en la nube y claude.ai:** en https://claude.ai/customize/connectors → *Add custom connector* → pega
  `https://<host-publico>/<MCP_SECRET_PATH>/mcp` (**sin la barra final**). Las sesiones nuevas lo cargan al iniciar.
- **Claude Code en el mismo PC:**
  `claude mcp add --scope user --transport http graphiti http://127.0.0.1:8000/mcp`

Consejo: usa un `group_id` distinto por proyecto (por ejemplo, el nombre del repo) para no mezclar los recuerdos.

## Seguridad
- La ruta secreta es la única llave: quien la tenga puede leer o borrar tu grafo. No la publiques en repos ni en capturas.
  Si se filtra, cambia `MCP_SECRET_PATH` en `.env` y ejecuta `docker compose --profile tailscale up -d` (o `--profile tunnel`).
- Cualquier petición sin la ruta secreta recibe un 404. Los puertos 8000 y 3000 solo escuchan en `127.0.0.1`.
- Autologin significa que quien tenga acceso físico al PC entra en tu sesión. Úsalo en un equipo que tengas en casa.
- `.env` está en `.gitignore`: nunca lo subas.

## Diagnóstico
`add_memory` siempre responde "queued": el episodio se procesa después, en segundo plano, y si falla se pierde. Para ver
los errores reales:
```powershell
docker compose logs --since 10m graphiti 2>&1 | Select-String -NotMatch "GET /health"
```

## Mantenimiento
- **Ver el grafo:** http://localhost:3000 (usa `localhost`, no `127.0.0.1`). Host `localhost`, puerto `6379`, sin usuario. Grafo: `default_db`.
- **Logs:** `docker compose logs -f graphiti`
- **Actualizar:** cambia la etiqueta de la imagen en `docker-compose.yml` y ejecuta `docker compose --profile tailscale up -d` (o `--profile tunnel`).
- **Backup:** `docker run --rm -v graphiti-mcp_falkordb_data:/d -v ${PWD}:/b alpine tar czf /b/backup.tgz -C /d .`

## Verificado
Probado con Docker (en Linux) usando keys de prueba: el servidor arranca con `gemini / gemini-3-flash-preview` y
`gemini / gemini-embedding-001` (reranker de Gemini), el `initialize` de MCP responde 200 por la ruta secreta y sin ella
se recibe 404. El `docker-compose.yml` con el perfil `tailscale` es válido (`docker compose config`), pero el contenedor de
Tailscale no se ha arrancado con una key real. Los scripts `.ps1` no se han ejecutado en Windows.
