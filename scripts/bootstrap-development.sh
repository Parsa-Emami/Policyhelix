#!/usr/bin/env bash
set -euo pipefail

# Run from the repository root after verifying the GitHub owner/module namespace.
# This script intentionally performs source bootstrap only; infrastructure credentials are never generated.

composer create-project laravel/laravel:^13.0 apps/control-plane
mkdir -p services/authn-gateway services/decision-service infra/envoy
(cd services/authn-gateway && go mod init github.com/Parsa-Emami/policyhelix/authn-gateway)
(cd services/decision-service && go mod init github.com/Parsa-Emami/policyhelix/decision-service)

printf "\nBootstrap command sequence completed. Review generated files, pin/lock dependencies, then run repository validation before commit.\n"
