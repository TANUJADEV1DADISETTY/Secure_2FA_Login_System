FROM node:22-alpine

WORKDIR /usr/src/app

# Install dependencies
COPY package*.json ./
RUN npm install --omit=dev

# Copy source code and files
COPY . .

# Expose API port
EXPOSE 3000

# Start application server (auto-runs migrations & seed on startup)
CMD ["node", "src/app.js"]
