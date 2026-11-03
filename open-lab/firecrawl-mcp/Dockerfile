# Versión fijada: se instala una vez al construir, no en cada arranque (como haría npx).
FROM node:22-alpine
RUN npm install -g firecrawl-mcp@3.36.0 && npm cache clean --force
USER node
EXPOSE 3000
CMD ["firecrawl-mcp"]
