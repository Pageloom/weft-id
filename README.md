# Setting up a dev-environment

1. Clone the repo
2. Generate dev-env certificates
   ```bash
   ./devscripts/mkdevcerts.sh
   ```
3. Generate an .env-file
   ```bash
   cp .env.dev.example .env
   ```
4. Run the app
    ```bash
    make up
    ```
5. Open your browser at https://dev.pageloom.localhost. (A dev tenant has been automatically provisioned for you)
