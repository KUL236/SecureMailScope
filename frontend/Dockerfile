FROM node:20-slim AS build
WORKDIR /app
COPY package.json .
RUN npm install
COPY . .
RUN npm run build

# The previous image served the built static files with `serve` and
# nothing else — that has no way to forward /api/* to the backend
# container, so every API call 404'd in production. nginx here both
# serves the static build and reverse-proxies /api to the backend
# service, matching what vite's dev proxy does locally.
FROM nginx:1.27-alpine
COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 5173
