# PolicyHelix — Implementation Commands v7.0

## Pre-flight
```bash
python3 --version
git --version
python3 scripts/validate_repo.py
```

## Source bootstrap
Review `scripts/bootstrap-development.sh`, verify the GitHub owner/module namespace where used, then run:
```bash
./scripts/bootstrap-development.sh
```

### Project-specific bootstrap sequence
```bash
composer create-project laravel/laravel:^13.0 apps/control-plane
mkdir -p services/authn-gateway services/decision-service infra/envoy
(cd services/authn-gateway && go mod init github.com/Parsa-Emami/policyhelix/authn-gateway)
(cd services/decision-service && go mod init github.com/Parsa-Emami/policyhelix/decision-service)
```

## First commit gate
```bash
python3 scripts/validate_repo.py
git status --short
# Review all generated manifests/lockfiles. Never commit .env, keys, tokens, certificates, DB dumps or source evidence.
```

The v7 package deliberately does not pretend framework source exists before bootstrap. The repository is ready to start implementation; the application is not yet implemented.
