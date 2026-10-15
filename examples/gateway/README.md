# Gateway example

A Reversi gateway in front of the built-in filesystem connector.

```sh
npm install && npm run build
node packages/connectors/dist/main.js manifests fs --format yaml > examples/gateway/manifests/fs.yaml
node packages/cli/dist/main.js policy test examples/gateway/policy.yaml
node packages/gateway/dist/main.js --config examples/gateway/gateway.yaml \
  --manifests examples/gateway/manifests --policy examples/gateway/policy.yaml
```

Then, after an agent has changed files in `sandbox/`:

```sh
node packages/cli/dist/main.js runs -m examples/gateway/manifests
node packages/cli/dist/main.js plan <run_id> -m examples/gateway/manifests
node packages/cli/dist/main.js rollback <run_id> -m examples/gateway/manifests \
  --compensator-cmd "node packages/connectors/dist/main.js compensate --root ./sandbox"
```
