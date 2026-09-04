#!/bin/bash
# Integration test: build + unit tests for the !get/!put protocol logic
set -e
cd "$(dirname "$0")"

echo "=== Building ==="
go build -o tp .
./tp version
echo ""

echo "=== Running Go tests ==="
go test -v -timeout 60s .
echo ""

echo "=== All tests passed ==="
