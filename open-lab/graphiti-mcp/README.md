# Graphiti MCP: memoria persistente para todos tus proyectos de Claude Code

Servidor [Graphiti MCP](https://github.com/getzep/graphiti/tree/main/mcp_server) en tu PC con Windows, publicado por un
**Cloudflare Tunnel** (sin abrir puertos) y protegido con una **ruta secreta**. Se añade una sola vez como connector en
claude.ai y queda disponible en todas tus sesiones de Claude Code en la nube.

```
Claude (nube) ──HTTPS──> Cloudflare ──túnel──> cloudflared ──> Caddy (ruta secreta) ──> Graphiti + FalkorDB
```

- **LLM:** Anthropic (`claude-haiku-5-5`), con tu API key de console.anthropic.com (no es la suscripción Pro/Max).
- **Embeddings y reranker:** Gemini (`gemini-embedding-001`, 768 dimensiones). Anthropic no ofrece embeddings, y con Gemini
  se evita la descarga de ~2.3 GB del reranker local.
- **Base de datos:** FalkorDB, dentro del mismo contenedor y con los datos en un volumen de Docker.

## Antes de empezar

1. **API keys:** Anthropic (console.anthropic.com, con un límite de gasto puesto) y Google (aistudio.google.com).
2. **Dominio en Cloudflare** (gratis añadirlo; el dominio cuesta unos 10 USD al año). Crea el túnel en
   Zero Trust → Networks → Tunnels → *Create a tunnel* → *Cloudflared* → *Docker*, y copia el **token**.
   En *Public hostname*: `graphiti.tu-dominio.com` → Service `HTTP` → `caddy:80`.

## Instalación (en el PC servidor)

```powershell
git clone https://github.com/Neckr0ik/Neckr0ik.git
cd Neckr0ik\open-lab\graphiti-mcp
powershell -ExecutionPolicy Bypass -File .\windows\1-instalar-graphiti.ps1
```

El script instala Docker Desktop si no lo tienes, te pide las keys y el token, genera la ruta secreta, levanta todo y
muestra la URL del connector.

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
4. **Túnel caído** (si defines `PUBLIC_HEALTH_URL`): reinicia `cloudflared`.
5. **Aviso externo** (si defines `HEALTHCHECKS_PING_URL`, gratis en healthchecks.io): si el PC se apaga, se va la luz o
   pierde internet, te llega un email. Esto el propio PC no lo puede avisar, por eso hace falta el monitor externo.

## Conectarlo a Claude

- **Todas las sesiones en la nube y claude.ai:** en https://claude.ai/customize/connectors → *Add custom connector* → pega
  `https://graphiti.tu-dominio.com/<MCP_SECRET_PATH>/mcp` (**sin la barra final**). Las sesiones nuevas lo cargan al iniciar.
- **Claude Code en el mismo PC:**
  `claude mcp add --scope user --transport http graphiti http://127.0.0.1:8000/mcp`

Consejo: usa un `group_id` distinto por proyecto (por ejemplo, el nombre del repo) para no mezclar los recuerdos.

## Seguridad
- La ruta secreta es la única llave: quien la tenga puede leer o borrar tu grafo. No la publiques en repos ni en capturas.
  Si se filtra, cambia `MCP_SECRET_PATH` en `.env` y ejecuta `docker compose --profile tunnel up -d`.
- Cualquier petición sin la ruta secreta recibe un 404. Los puertos 8000 y 3000 solo escuchan en `127.0.0.1`.
- Autologin significa que quien tenga acceso físico al PC entra en tu sesión. Úsalo en un equipo que tengas en casa.
- `.env` está en `.gitignore`: nunca lo subas.

## Mantenimiento
- **Ver el grafo:** http://127.0.0.1:3000
- **Logs:** `docker compose logs -f graphiti`
- **Actualizar:** cambia la etiqueta de la imagen en `docker-compose.yml` y ejecuta `docker compose --profile tunnel up -d`.
- **Backup:** `docker run --rm -v graphiti-mcp_falkordb_data:/d -v ${PWD}:/b alpine tar czf /b/backup.tgz -C /d .`

## Verificado
Probado con Docker (en Linux) usando keys de prueba: el servidor arranca con `anthropic / claude-haiku-5-5` y
`gemini / gemini-embedding-001` (reranker de Gemini), el `initialize` de MCP responde 200 por la ruta secreta y sin ella
se recibe 404. Los scripts `.ps1` no se han ejecutado en Windows.
