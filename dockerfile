# Produktionssicheres Playwright-Image (Chromium inkl. System-Dependencies)
FROM mcr.microsoft.com/playwright:v1.46.0-jammy

# Arbeitsverzeichnis
WORKDIR /app

# Nur package.json zuerst – bessere Layer-Caches
COPY package.json ./

# Dependencies installieren + Playwright-Browser sicherstellen
RUN npm ci && npx playwright install --with-deps chromium

# Rest des Codes
COPY . .

# Prod-Start
ENV NODE_ENV=production
EXPOSE 3000
CMD ["npm", "run", "start:prod"]
