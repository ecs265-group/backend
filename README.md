# Steps to run the server

1. Docker and docker-compose should be installed on your machine.
2. Clone the repository.
3. Go to the `backend` directory.
4. Run the following command to start the server:
```bash
docker-compose up -d --build
```
5. Run the following commands to start the ResilientDB KV service (it isn't started by default):
```bash
docker exec resid-core-backend bash -c "cd /resdb && chmod +x INSTALL.sh && chmod +x service/tools/kv/server_tools/start_kv_service.sh && ./INSTALL.sh && service/tools/kv/server_tools/start_kv_service.sh"
```
6. Verify the KV service is running by running the following commands:
```bash
curl -X POST -d '{"id":"key1","value":"value1"}' 127.0.0.1:18000/v1/transactions/commit
curl 127.0.0.1:18000/v1/transactions/key1
```
7. The server should be running on `http://localhost:8000/`. Visit `http://localhost:8000/api` to verify the server is running.
