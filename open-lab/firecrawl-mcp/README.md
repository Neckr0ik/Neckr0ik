# Firecrawl MCP: scraping autoalojado para todas tus sesiones de Claude

Servidor [firecrawl-mcp](https://github.com/firecrawl/firecrawl-mcp-server) en modo HTTP, conectado a un
[Firecrawl](https://github.com/firecrawl/firecrawl) self-hosted y publicado con **Tailscale Funnel**, sin abrir puertos y
protegido con una **ruta secreta**. Mismo patrón que [`../graphiti-mcp`](../graphiti-mcp).

```
Claude (nube) ──HTTPS──> Tailscale Funnel ──> contenedor tailscale ──> Caddy (ruta secreta) ──> firecrawl-mcp ──> Firecrawl API (host:3002)
```

## Antes de empezar: Tailscale
Tailscale corre como contenedor (no hace falta instalarlo en Windows). Si ya configuraste `../graphiti-mcp`, los dos
primeros pasos ya están hechos. En https://login.tailscale.com/admin:
1. *DNS* → activa **MagicDNS** y **HTTPS Certificates**.
2. *Access controls* → permite Funnel: `"nodeAttrs": [{"target": ["autogroup:member"], "attr": ["funnel"]}]`.
3. *Settings → Keys* → *Generate auth key*: **Reusable** sí, **Ephemeral** no y **sin tags** (un nodo con tag deja de
   ser de `autogroup:member` y la regla de Funnel no lo cubre).

## Instalación (un solo script)
```powershell
cd Neckr0ik\open-lab\firecrawl-mcp
powershell -ExecutionPolicy Bypass -File .\windows\1-instalar-firecrawl.ps1
```
El script se puede volver a ejecutar cuando quieras: solo crea lo que falta.

| Paso | Qué hace |
|---|---|
| Docker | Lo instala con winget si falta; comprueba que Docker Desktop esté corriendo |
| Firecrawl | Lo clona en `$HOME\firecrawl` si no existe, copia `firecrawl/firecrawl.env` como `.env` y siempre actualiza `docker-compose.override.yaml`; `docker compose up -d --build` (la primera vez, 10-20 min) |
| Keys | Crea `.env` y genera `MCP_SECRET_PATH` (192 bits, CSPRNG). Pide `TS_AUTHKEY` solo si falta, **sin mostrarla** en pantalla, y comprueba que empiece con `tskey-` |
| MCP | `docker compose up -d --build` de este proyecto y espera a `127.0.0.1:3010/health` |
| Claude Code local | Registra `firecrawl` → `http://127.0.0.1:3010/mcp` (scope user) |
| URL pública | Obtiene el dominio `*.ts.net` del contenedor, prueba `/health` por Funnel y te muestra la URL del connector |

Opciones: `-NuevaKey` vuelve a pedir la key de Tailscale (si caducó), `-NuevoSecreto` cambia la ruta secreta (la URL
anterior deja de funcionar) y `-FirecrawlDir <ruta>` usa otra carpeta para Firecrawl.

## Conectarlo a Claude
- **Sesiones en la nube, app del celular y claude.ai:** https://claude.ai/customize/connectors → *Add custom connector* →
  pega la URL pública (**sin la barra final**).
- **Claude Code en este PC:** `claude mcp add --scope user --transport http firecrawl http://127.0.0.1:3010/mcp`

## Detalles
- **Red:** `firecrawl-mcp` llega a la API por la red interna de Docker `firecrawl_backend` (`http://api:3002`). El
  `docker-compose.yml` original de Firecrawl publica el 3002 en `0.0.0.0`, así que la API (sin autenticación) queda abierta a
  toda tu red local. El override de `firecrawl/` lo deja solo en `127.0.0.1` (usa `!override`, Docker Compose 2.24+).
- `firecrawl-mcp` rechaza con 403 las peticiones cuyo `Host`/`Origin` no es `localhost`. Por eso Caddy reescribe `Host` y
  quita `Origin`. La protección real es la ruta secreta: sin ella, Caddy responde 404.
- La versión de `firecrawl-mcp` está fijada en el `Dockerfile`. Para actualizar: cambia la versión y ejecuta
  `docker compose up -d --build`.
- Firecrawl self-hosted no tiene IA configurada: `firecrawl_agent`, `extract` y las herramientas de búsqueda o de la nube
  de Firecrawl pueden fallar. Lo que funciona es `scrape`, `crawl`, `map` y `parse`.
- Salud: `https://<host>/<MCP_SECRET_PATH>/health`.

## Seguridad
- Quien tenga la ruta secreta puede usar tu PC para scrapear cualquier web. No la publiques. Si se filtra, cámbiala en
  `.env` y ejecuta `docker compose up -d`.
- El puerto 3010 solo escucha en `127.0.0.1`. `.env` está en `.gitignore`.

## Diagnóstico
```powershell
docker compose logs -f firecrawl-mcp      # MCP
docker compose logs tailscale             # login de Tailscale / Funnel
cd $HOME\firecrawl; docker compose logs -f api   # Firecrawl
```

## Verificado
En Windows 11 con Docker Desktop: `initialize` y `tools/list` responden por `127.0.0.1:3010` y por Caddy con la ruta
secreta (también con `Origin: https://claude.ai`); sin la ruta secreta se recibe 404; `firecrawl_scrape` de
`https://example.com` devuelve el markdown por la red `firecrawl_backend`; el 3002 ya no responde desde la IP de la LAN.
El script se ejecutó completo en Windows PowerShell 5.1 con una key real: por Funnel, `/health` responde 200,
`initialize` responde (con `Origin: https://claude.ai`) y sin la ruta secreta se recibe 404.

**DNS de un nodo nuevo:** el certificado HTTPS sale en ~30 s, pero el registro DNS público de Funnel tardó ~5 min en
existir, y los resolvers guardan el "no existe" otros 5 min (TTL negativo 300 s). El script pregunta al DNS autoritativo
de la tailnet y prueba con `curl.exe --resolve` para no depender de esas cachés. Si al principio el navegador dice que el
dominio no existe, espera unos minutos.
