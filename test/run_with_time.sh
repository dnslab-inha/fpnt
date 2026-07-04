#!/bin/bash
# Wrapper script to run tests with `/usr/bin/time -v` to measure maximum memory usage.
# It skips timing during doctest's test discovery phase.

is_discovery=0
for arg in "$@"; do
  if [[ "$arg" == "--list-test-cases" || "$arg" == "--list-test-suites" ]]; then
    is_discovery=1
  fi
done

if [ $is_discovery -eq 1 ]; then
  exec "$@"
else
  if command -v time >/dev/null 2>&1; then
    if [[ "$(uname)" == "Darwin" ]]; then
      exec /usr/bin/time -l "$@"
    else
      exec /usr/bin/time -v "$@"
    fi
  else
    exec "$@"
  fi
fi
