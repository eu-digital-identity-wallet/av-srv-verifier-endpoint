# Step by step: Run the Age Verification verifier locally

## Description
Step-by-step guide on how to run the Age Verification verifier locally using Docker.

> [!NOTE]
> This setup runs **only the OpenID4VP** verification flow. No other protocols are supported.

## Requirements
- docker
- git

Make sure no other services are running on ports **443, 8080, 9090**!

## Run Docker
Make sure Docker is up to date and running!

## Run the backend of the verifier
*Note: this will run some extra services that are not needed, but that is not important.*

Run command:

```
git clone https://github.com/eu-digital-identity-wallet/av-srv-verifier-endpoint.git
```

Run command:

```
cd av-srv-verifier-endpoint
```

Run commands:

```
cd docker
docker compose up -d
```

## Age Verification UI – clone

```
git clone https://github.com/eu-digital-identity-wallet/av-web-verifier-ui.git
cd av-web-verifier-ui
```

## Run the Age Verification UI
*Warning: Do not run `npm install` locally!*

- Delete the file `package-lock.json`
- Delete the folder `node_modules` if present

Run command:

```
echo "VITE_VERIFIER_BASE_URL=http://localhost:8080" > .env
```

Run command:

```
docker run -p 9090:80 --rm -it $(docker build -q .)
```

## Open browser

[http://localhost:9090](http://localhost:9090)

---

# Step by step: Run the DC-API (multipaz) backend locally

## Description
Step-by-step guide on how to run the **DC-API verifier backend** (multipaz-based) locally.

> [!NOTE]
> This backend serves the **Digital Credentials API (DC-API)** verification flow and is a separate backend from the OpenID4VP one above.

## Requirements
- git
- JDK 17 (for the Gradle option), **or** docker (for the Docker option)

Make sure no other service is running on port **8006**!

## Backend – clone

```
git clone https://github.com/T-Scy/av-dc-api-multipaz-backend.git
cd av-dc-api-multipaz-backend
```

## Run the backend

### Option A – Gradle (recommended for development)

Run command:

```
./gradlew multipaz-verifier-server:run
```

The backend now listens on [http://localhost:8006](http://localhost:8006).

### Option B – Docker

Build the fat jar:

```
./gradlew :multipaz-verifier-server:buildFatJar
```

Build and run the image:

```
cd multipaz-verifier-server
docker build -t av-dc-api-backend .
docker run -p 8006:8006 --rm -it av-dc-api-backend
```

## CORS

The allowed browser origins are read from the `cors_allowed_origins` configuration
value (comma-separated, `scheme://host[:port]`). By default `http://localhost:5173`
and `http://localhost:9090` are allowed, which covers both the Vite dev server and
the Docker-based Age Verification UI.

To allow a different origin, start the backend with it configured:

```
./gradlew multipaz-verifier-server:run --args="-param cors_allowed_origins=https://my-ui.example.com"
```

## Run the Age Verification UI against this backend

Follow the **Age Verification UI** steps above, but point the UI at the DC-API backend:

```
Copy .env.example and set following values:
VITE_VERIFIER_BASE_URL=http://localhost:8080
VITE_DC_API_VERIFIER_BASE_URL=http://localhost:8006
VITE_FEATURE_FLAG_DC_API=true
```

## Open browser

[http://localhost:9090](http://localhost:9090)
