#!/bin/bash

set -xeo pipefail

# shellcheck disable=SC2086
RUSTFLAGS="-C target-feature=+bmi2,+adx --emit=asm" cargo $CARGOARGS test --all-features
