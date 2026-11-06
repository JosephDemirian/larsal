# Appended to check.sh's own text, cut before its first gate line. Same bodies; the additions are one row per step and the phase call.
# LOGS and GC_STEPS come from the lines the tool puts in front of this text.
run() {
  local step=$1 t0 rc
  shift
  t0=$(/bin/date +%s)
  "$@" >"$LOGS/$step.log" 2>&1
  rc=$?
  printf '%s\t%s\t%s\n' "$step" "$rc" "$(($(/bin/date +%s) - t0))" >>"$GC_STEPS"
  [ "$rc" -eq 0 ] && return 0
  bad="$bad $step"
  echo "--- $step FAILED. Last lines of $LOGS/$step.log:"
  tail -n 30 "$LOGS/$step.log"
  return 1
}
fuzz_wait() {
  local pid step rc
  while [ "$#" -gt 0 ]; do
    pid=$1 step=$2
    shift 2
    wait "$pid"
    rc=$?
    printf '%s\t%s\t\n' "$step" "$rc" >>"$GC_STEPS"
    if [ "$rc" -ne 0 ]; then
      bad="$bad $step"
      echo "--- $step FAILED. Last lines of $LOGS/$step.log:"
      tail -n 30 "$LOGS/$step.log"
    fi
  done
}
# check.sh's cargo test lines also run the doc tests; the guarded route runs them as these three lanes.
docs() {
  run doc-workspace cargo test --offline --locked --workspace --doc
  run doc-sync cargo test --offline --locked -p larsal-ffi --features sync --doc
  run doc-net cargo test --offline --locked -p larsal-platform --features net --doc
}
"$1"
echo "GC_NOTE $note"
[ -z "$bad" ]
