#!/bin/bash

workdir="$( cd "$( dirname "${BASH_SOURCE[0]}" )/../.." &> /dev/null && pwd )"
globals="$(docker run --rm -v "$workdir":/workdir mikefarah/yq e '.env.global | join(" ")' .travis.yml)"
mapfile -t jobs < <(docker run --rm -v "$workdir":/workdir mikefarah/yq e '.env.jobs.[]' .travis.yml)

for i in "${!jobs[@]}"; do
  # shellcheck disable=SC2086
  eval $globals ${jobs[$i]} "$workdir"/ci/script.sh 2>&1 | tee -a "$workdir/ci/devtools/job-$i.log"
  break
done
