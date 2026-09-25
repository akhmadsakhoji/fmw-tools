#!/usr/bin/env bash
# Builds release archives for every supported system into dist/.
# Usage: scripts/build-release.sh <version tag, e.g. v0.1.0>   ("ci" only builds)
set -euo pipefail

tag="${1:?give the version tag, for example v0.1.0}"
version="${tag#v}"
targets="linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64"

rm -rf dist
mkdir -p dist
for target in $targets; do
  os="${target%/*}"
  arch="${target#*/}"
  name="fmw-tools_${version}_${os}_${arch}"
  bin="fmw-tools"
  [ "$os" = windows ] && bin="fmw-tools.exe"
  mkdir -p "dist/$name"
  CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -trimpath \
    -ldflags "-s -w -X main.version=$version" -o "dist/$name/$bin" ./cmd/fmw-tools
  [ "$tag" = ci ] && continue
  cp README.md LICENSE CHANGELOG.md "dist/$name/"
  if [ "$os" = windows ]; then
    (cd dist && zip -qr "$name.zip" "$name")
  else
    tar -C dist -czf "dist/$name.tar.gz" --owner=0 --group=0 "$name"
  fi
  rm -rf "dist/$name"
done
if [ "$tag" = ci ]; then
  ls -l dist/*/
  rm -rf dist
  exit 0
fi
(cd dist && sha256sum fmw-tools_* > SHA256SUMS)
ls -l dist
