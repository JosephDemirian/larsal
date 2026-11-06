#!/bin/bash
# The lane, inside the one outer sandbox. Nothing here starts sandbox-exec. Each step's log goes to the attempt's folder.
#   lane.sh A <out>   build-core, build-for-testing, then compile the APP-09 program without running it
#   lane.sh B <out>   test-without-building, then the APP-09 cargo line
#   lane.sh G <out>   G1's Swift steps: the check.sh swift format and SwiftLint commands, word for word
stage=$1
out=$2
# Added flags, each with its reason.
#   -IDEPackageSupportDisableManifestSandbox=1, ENABLE_USER_SCRIPT_SANDBOXING=NO, OTHER_SWIFT_FLAGS -disable-sandbox: a nested sandbox cannot start inside the one outer sandbox.
#   -derivedDataPath target/xcode, -resultBundlePath under lane-out: build output and results stay under the root.
#   -packageAuthorizationProvider netrc: no keychain for package authorization.
#   -disableAutomaticPackageResolution, -skipPackageUpdates: offline, nothing is fetched.
#   -collect-test-diagnostics never: without it a system log archive of about 400 MB lands in /private/var/tmp, outside the root.
#   -skip-testing:LarsalUITests: UI tests would drive a real window; they never run.
#   SWIFT_TREAT_WARNINGS_AS_ERRORS=YES: the board's rule for this build.
XB=(-IDEPackageSupportDisableManifestSandbox=1 -project macos/Larsal.xcodeproj -scheme Larsal -destination platform=macOS -derivedDataPath target/xcode -packageAuthorizationProvider netrc -disableAutomaticPackageResolution -skipPackageUpdates -collect-test-diagnostics never)
XS=(-skip-testing:LarsalUITests SWIFT_TREAT_WARNINGS_AS_ERRORS=YES ENABLE_USER_SCRIPT_SANDBOXING=NO 'OTHER_SWIFT_FLAGS=$(inherited) -disable-sandbox')
swift_format() { swift format lint --strict --recursive macos; }
swiftlint_lint() {
  local bin
  bin=$(scripts/install-swiftlint.sh --path)
  [ -x "$bin" ] || { echo "SwiftLint is not installed: run scripts/install-swiftlint.sh"; return 1; }
  (cd macos && "$bin" lint --strict --quiet)
}
step() {
  local n=$1
  shift
  echo "STEP $n start $(/bin/date +%s)"
  "$@" >"$out/$n.stdout" 2>"$out/$n.stderr"
  local rc=$?
  echo "STEP $n exit $rc $(/bin/date +%s)"
  return $rc
}
case $stage in
  A)
    step build-core scripts/build-core.sh || exit $?
    step xcode-build xcodebuild "${XB[@]}" -resultBundlePath "$out/build.xcresult" build-for-testing "${XS[@]}" || exit $?
    step app09-build cargo test --offline --locked -p larsal-ffi --test app09 --no-run --message-format=json
    ;;
  B)
    step xcode-test xcodebuild "${XB[@]}" -resultBundlePath "$out/test.xcresult" test-without-building "${XS[@]}"
    a=$?
    step results xcresulttool get test-results summary --path "$out/test.xcresult" --compact
    step app09 cargo test --offline --locked -p larsal-ffi --test app09
    b=$?
    exit $((a ? a : b))
    ;;
  G)
    step swift-format swift_format
    a=$?
    step swiftlint swiftlint_lint
    b=$?
    exit $((a ? a : b))
    ;;
  *)
    echo "unknown stage $stage" >&2
    exit 2
    ;;
esac
