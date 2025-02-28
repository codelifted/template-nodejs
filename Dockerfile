# Build stage
FROM node:18 AS builder
WORKDIR /app
COPY package*.json ./
RUN npm install

# Runtime stage
FROM node:18
WORKDIR /app
COPY --from=builder /app/node_modules ./node_modules
COPY src/ ./src/
EXPOSE 3000
CMD ["npm", "start"]