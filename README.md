# Lundakarnevalen Train API
> An API for the lundakarnevalen train

## Running the API server
To run the API server you need to set these environment variables before running the program:

- `TRAIN_API_PORT`, the port to bind to.
- `TRAIN_API_POSITION_FILE`, the location to save the last received position.
- `TRAIN_API_CRED_TOKEN`, the token used for authenticating users trying to set the position. 
- `TRAIN_API_CERT_FILE`, the certificate for https.
- `TRAIN_API_KEY_FILE`, the private key for https. 

Example for running in bash, dev build: 
```BASH
TRAIN_API_PORT=8080 TRAIN_API_POSITION_FILE=./position.json TRAIN_API_CRED_TOKEN=very-secret-token TRAIN_API_CERT_FILE=./cert.pem TRAIN_API_KEY_FILE=./priv_key.pem cargo run
```
