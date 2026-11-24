# Análisis rápido · Neckr0ik/Neckr0ik · 24-nov-2026

Diagnóstico sin cambios de código. Base: `main` en `0f8d065`.

## 1. Qué es

Este es el repositorio de perfil de GitHub: su `README.md` es lo que se ve en github.com/Neckr0ik. Hoy junta tres cosas con públicos y ciclos de vida distintos:

| Bloque | Contenido | Público natural |
|:---|:---|:---|
| Documentación | Perfil, Founder Track, *Hybrid Intelligence* (método y build log), fundamentos de seguridad/GRC (`1-…` a `5-…`), `docs/` | Reclutadores, socios |
| Open Lab | 5 paquetes Python independientes con `pyproject.toml`, `src/`, tests y licencia MIT | Investigadores, desarrolladores |
| Infraestructura | `open-lab/graphiti-mcp`: Docker Compose, Caddy, Tailscale/Cloudflare y scripts PowerShell para un servidor doméstico | Solo el autor |

## 2. Estado

- **Fortalezas.** El perfil está bien armado y es multilingüe. Los paquetes tienen *src layout*, CLI, licencia y tests. Hay CI en Python 3.11 y 3.12, y la parte de ética y seguridad está documentada. Las cifras de tests del README coinciden con la realidad (ver §3).
- **Señal mezclada.** 11 de los últimos 15 commits son de `graphiti-mcp`. Quien entra al repositorio de perfil ve sobre todo trabajo de infraestructura personal y no el método.
- **Deuda concreta:**
  1. Ningún paquete está en PyPI. Para usar uno hay que clonar el perfil entero e instalar con `pip install -e`.
  2. En cada `pyproject.toml`, `Homepage` apunta a `github.com/Neckr0ik` y no al paquete. Faltan `Repository`, `Issues` y `Changelog`.
  3. `llm-gateway-metering` usa `license = { file = … }` y el clasificador de licencia. Con setuptools reciente eso da *BuildBackendWarning*, y setuptools anuncia que deja de construir con esa sintaxis el **18-feb-2027**. Hay que cambiarlo a `license = "MIT"` y `license-files`, como ya hacen `mx-census-sampler` y `endutih-media-profiles`. `llm-survey-bias-kit` y `silicon-sample-validation` usan la misma tabla con hatchling, y conviene unificarlos.
  4. El `requirements.txt` de la raíz no lo usa nadie y confunde. Además, dos paquetes duplican sus dependencias en `requirements*.txt`, aparte del `pyproject.toml`.
  5. `graphiti-mcp` no tiene validación en CI (ni siquiera `docker compose config`), y su README instala con `git clone` **del repositorio de perfil**.
  6. No hay tags, releases ni CHANGELOG por paquete; todos siguen en `0.1.0`.

## 3. Tests (verificados en esta sesión)

Se instaló cada paquete en un entorno virtual aislado (`pip install -e . pytest` más `requirements-dev.txt` cuando existe) y se corrió `pytest -q`, igual que en CI. Se usó **Python 3.13**; CI corre en 3.11 y 3.12.

| Paquete | Resultado |
|:---|:---|
| mx-census-sampler | 33 pasan |
| endutih-media-profiles | 19 pasan |
| llm-survey-bias-kit | 87 pasan |
| silicon-sample-validation | 85 pasan, 1 omitido (requiere SDK de Anthropic) |
| llm-gateway-metering | 65 pasan, 2 omitidos (SDK o llave real) |
| packet-sniffer-scapy | 5 pasan |

Total del Open Lab: **289 pasan y 3 omitidos, 292 tests**, igual que el README. Como dato extra, los 5 paquetes corren en 3.13, que CI todavía no cubre.

## 4. Plan de separación (propuesto, no ejecutado)

### Recomendación

1. **Paquetes → un monorepo `open-lab` en la organización `impulselabs-mx`, con publicación en PyPI.**
   - Es mejor que 5 repositorios sueltos: se mantiene un solo CI (la matriz actual se copia tal cual), se aplica una sola política de seguridad y licencias, y el diagrama de flujo entre paquetes cobra sentido. Cada paquete conserva su `pyproject.toml` y su versión propia.
   - Se publica con tags por paquete (`mx-census-sampler-v0.1.1`) y *Trusted Publishing* de PyPI desde GitHub Actions, sin tokens guardados.
   - Los 5 nombres están **libres en PyPI** hoy (consultado el 24-nov-2026). Conviene reservarlos pronto con una primera versión.
   - Alternativa: repositorios individuales solo para el o los paquetes con más tracción (por ejemplo `llm-survey-bias-kit`), si se quiere fijar cada uno en el perfil.
2. **`graphiti-mcp` → repositorio privado** (por ejemplo `Neckr0ik/graphiti-mcp`). Es infraestructura personal, no forma parte del método y su exposición no aporta al portafolio.
3. **El perfil queda como hub.** Conserva el README, *Hybrid Intelligence*, los fundamentos de seguridad/GRC y `docs/`, con enlaces a `open-lab` y a PyPI.

### Pasos

1. Extraer el historial de cada carpeta con `git filter-repo --subdirectory-filter` (o `git subtree split`) y conservar la autoría y los commits.
2. Crear `impulselabs-mx/open-lab` con el workflow actual, añadir el job `publish.yml` (build → TestPyPI → PyPI con `id-token: write`) y publicar `0.1.1` de cada paquete con los metadatos corregidos (§2, puntos 2 y 3).
3. Crear el repositorio privado de `graphiti-mcp` y añadir un job `docker compose config` con un `.env` de ejemplo.
4. En el perfil, cambiar `open-lab/` por un README breve que redirija y quitar `graphiti-mcp`.
5. Esperar una semana con los enlaces nuevos funcionando y luego borrar las carpetas del perfil.

### Riesgos y cómo atenuarlos

| Riesgo | Atenuación |
|:---|:---|
| Enlaces rotos (citas, DOIs, posts que apuntan a `Neckr0ik/Neckr0ik/tree/main/open-lab/...`) | Dejar `open-lab/README.md` como página de redirección permanente con la tabla de paquetes y los enlaces nuevos |
| Pasar `graphiti-mcp` a privado **no borra** su historial público | No hace falta reescribir la historia: `.env` nunca se subió (está en `.gitignore`) y solo hay `.env.example`. Aun así, conviene revisarla una vez con un escáner de secretos antes de mover |
| El instalador de Windows hace `git clone` de un repositorio público; ya privado, pide autenticación | Documentar el `gh auth login` o una *deploy key* de solo lectura en el PC servidor y probarlo antes de borrar la copia pública |
| Las sesiones de IA ligadas al repositorio de perfil dejan de ver el código de los paquetes | Añadir el nuevo repositorio a las sesiones y llevar el bloque de comandos de `CLAUDE.md` al monorepo |
| Publicar en PyPI compromete nombres y versiones | Usar SemVer desde `0.1.x`, mantener un CHANGELOG y no publicar datos que no sean de INEGI. Los CSV del Censo ya van dentro del wheel; revisar el tamaño y los términos de libre uso en el README de PyPI |
| La organización `impulselabs-mx` mezcla la marca de la empresa con código personal | Es una decisión de marca. La alternativa neutral es `Neckr0ik/open-lab` |

### Enlaces que hay que actualizar

- `README.md` (9 referencias a `open-lab/`, el badge «Open Lab · 5 packages» y la tabla del Open Lab).
- `hybrid-intelligence/README.md` (2), `docs/CONTRIBUTING.md` (3) y `CLAUDE.md` (5 y la sección de `graphiti-mcp`).
- `.github/workflows/open-lab.yml`: se queda solo con el job `packet-sniffer`, o con un job nuevo para los fundamentos.
- `[project.urls]` de cada `pyproject.toml`: `Homepage`, `Repository`, `Issues` y `Changelog`.
- `open-lab/graphiti-mcp/README.md`: la URL de `git clone`.

## 5. Conectores (evaluados, ninguno activado)

| Conector | Uso concreto | Valor |
|:---|:---|:---|
| **GitHub (releases)** | (1) Tags y releases por paquete con notas generadas desde Conventional Commits. (2) Trusted Publishing a PyPI desde Actions. (3) Revisar las *topics* del repositorio para que aparezca en búsquedas (`silicon-samples`, `survey-methodology`, `inegi`) | Alto, y ya está disponible |
| **Vercel** | Sitio de documentación del Open Lab (MkDocs Material o Astro Starlight) con una página por paquete, ejemplos de CLI y la ficha de método, desplegado en cada push a `main` de `open-lab` en un subdominio propio | Medio: conviene hacerlo una vez que existan los paquetes en PyPI |
| **Firecrawl** | (1) `firecrawl_scrape` del perfil y de las páginas de PyPI para ver cómo los ve un buscador. (2) `firecrawl_monitor` semanal sobre el perfil, para detectar enlaces rotos después de la separación | Medio, barato |
| **Semrush** | Poco útil para `github.com/Neckr0ik`, porque mide dominios y no subrutas de GitHub. Sirve si el sitio de docs vive en un dominio propio: `keyword_research` para términos como «silicon sample», «muestreo censo México» o «LLM survey bias» | Bajo hoy, medio con un dominio propio |
| **Notion** | Borrador privado del build log: entradas en Notion que, una vez revisadas, se pasan a la tabla de `hybrid-intelligence/README.md`. El repositorio sigue siendo la fuente pública | Bajo a medio; solo vale si ya se usa Notion a diario |

## 6. Tres siguientes pasos

1. **Corregir los metadatos de empaquetado** (licencia SPDX, `project.urls`, quitar el `requirements.txt` raíz) y añadir Python 3.13 a la matriz de CI. Es poco trabajo, quita el aviso de 2027 y prepara PyPI.
2. **Crear `open-lab` como monorepo con historial y publicar `0.1.1` de los 5 paquetes en PyPI** para reservar los nombres.
3. **Mover `graphiti-mcp` a un repositorio privado** con validación `docker compose config` y dejar el perfil como hub de documentación.

## 7. Nota: Nemotron frente a la verificación

Para el primer avance se usó Nemotron (`nvidia/nemotron-3-super-120b-a12b`). La herramienta `opencode_run` de OPENCODE falló porque su servidor pasa la opción `--dir`, que la CLI no reconoce. Por eso la consulta se hizo directamente por OpenRouter con un resumen del repositorio, sin secretos.

- **Acertó:** que falta PyPI, que el `requirements.txt` raíz sobra, que `graphiti-mcp` no tiene CI y es poco portable, que conviene sacarlo a un repositorio privado, que el perfil debe quedar como hub y que conviene automatizar releases.
- **Se equivocó o exageró:**
  - Dijo que la CI «solo compila»: en realidad corre los 289 tests offline.
  - Sugirió proteger el «know-how» de `graphiti-mcp` al hacerlo privado, pero ese código ya es público en el historial y no contiene secretos.
  - Planteó que un monorepo «acopla» los paquetes: siguen siendo independientes, cada uno con su `pyproject.toml`.
- **No vio** (tampoco podía, solo tenía el resumen): la fecha límite de setuptools, que los nombres están libres en PyPI, que el README de `graphiti-mcp` clona el repositorio de perfil ni la lista de enlaces que hay que actualizar.
