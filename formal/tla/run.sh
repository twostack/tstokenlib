#!/bin/sh
# Model-check PoolRounds.tla under every configuration in this directory
# (or the ones given). Needs java; fetches tla2tools.jar beside this script
# if it is not there. A violated configuration prints the actions of its
# counterexample; TRACE=1 prints the full trace.
cd "$(dirname "$0")" || exit 1
[ -f tla2tools.jar ] || curl -sL -o tla2tools.jar https://github.com/tlaplus/tlaplus/releases/latest/download/tla2tools.jar
status=0
for cfg in ${@:-*.cfg}; do
  name=${cfg%.cfg}
  out=$(java -XX:+UseParallelGC -cp tla2tools.jar tlc2.TLC -workers auto -config "$cfg" PoolRounds.tla 2>&1)
  states=$(printf '%s\n' "$out" | grep -o '[0-9,]* distinct states' | tail -1)
  if printf '%s\n' "$out" | grep -q 'is violated'; then
    inv=$(printf '%s\n' "$out" | grep -o 'Invariant [A-Za-z]* is violated' | head -1 | awk '{print $2}')
    printf '%-28s VIOLATED %-22s %s\n' "$name" "$inv" "$states"
    printf '%s\n' "$out" | grep -o '^State [0-9]*: <[A-Za-z0-9]*' | sed 's/^State \([0-9]*\): </    \1. /' | tail -n +2
    [ -n "$TRACE" ] && printf '%s\n' "$out" | sed -n '/The behavior up to this point/,/distinct states/p'
    case $name in Attack_*) ;; *) status=1 ;; esac
  elif printf '%s\n' "$out" | grep -q 'Model checking completed. No error'; then
    printf '%-28s holds    %-22s %s\n' "$name" "" "$states"
    case $name in Attack_*) status=1 ;; esac
  else
    printf '%-28s ERROR\n' "$name"; printf '%s\n' "$out" | grep -A8 '^Error' | head -30; status=1
  fi
done
exit $status
