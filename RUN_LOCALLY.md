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
