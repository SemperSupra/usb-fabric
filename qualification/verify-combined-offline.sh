#!/usr/bin/env bash
# Offline source qualification only. No Docker, no host mutation or network downloads.
set -Eeuo pipefail
cd "$(git rev-parse --show-toplevel)"
[[ -z "$(git status --porcelain --untracked-files=all)" ]] || { echo DIRTY_SOURCE=RED; exit 10; }
python3 -B qualification/verify-source-convergence.py
python3 -B qualification/verify-three-kernel-adoption.py
export GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOWORK=off
go version
for module in releasegate integrated; do
  (cd "experiments/usb-fabric-r26/$module" && go test -race -count=1 -timeout=120s ./... && go vet ./...)
done
python3 -B -c 'import ast; ast.parse(open("experiments/usb-fabric-r26/integrated/protected_signed_hid_oracle.py").read())'
[[ -z "$(git status --porcelain --untracked-files=all)" ]] || { echo DIRTY_AFTER=RED; exit 11; }
echo COMBINED_OFFLINE_SOURCE=PASS
