#!/usr/bin/env bash
# End-to-end test of ret_basic against a real, isolated rnsd and the Python
# test peer. Proves the four goals: TCP + HDLC framing, announce
# validation, encrypted DATA delivery, delivery-proof validation.
#
# Scenarios:
#   plain     peer proves every packet           -> 3/3 delivered, exit 0
#   ratchets  peer announces with ratchets       -> 3/3 delivered, exit 0
#   no-prove  peer never proves                  -> 3 timeouts,    exit 1
#
# Run from anywhere inside the west workspace with the Zephyr toolchain
# environment active (see AGENTS.md). Pass scenario names to run a subset.
# Logs land in build/ret_e2e-logs/.
set -euo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
RET=$(cd "$HERE/.." && pwd)
TOP=$(west topdir)
BUILD="$TOP/build/ret_e2e"
# Not under $BUILD: a pristine build wipes that directory.
LOGS="$TOP/build/ret_e2e-logs"
PEER_PROJECT="$HERE/rns_peer"
RNSD_CONFIG="$HERE/rnsd-test"
PORT=4243
COUNT=3

scenarios=("$@")
[ ${#scenarios[@]} -gt 0 ] || scenarios=(plain ratchets no-prove)

pids=()
cleanup() {
	for pid in "${pids[@]}"; do
		kill "$pid" 2>/dev/null || true
	done
	wait 2>/dev/null || true
}
trap cleanup EXIT

fail() {
	echo "FAIL: $*" >&2
	exit 1
}

wait_for() { # <seconds> <description> <command...>
	local deadline=$((SECONDS + $1)) what=$2
	shift 2
	until "$@" 2>/dev/null; do
		[ $SECONDS -lt $deadline ] || fail "timed out waiting for $what"
		sleep 0.2
	done
}

port_open() { (exec 3<>"/dev/tcp/127.0.0.1/$PORT") 2>/dev/null; }

mkdir -p "$LOGS"

echo "== build ret_basic (port $PORT, $COUNT messages)"
west build -b native_sim "$RET/samples/ret_basic" -d "$BUILD" -p -- \
	-DCONFIG_RET_SERVER_PORT=$PORT \
	-DCONFIG_RET_SAMPLE_MESSAGE_COUNT=$COUNT \
	-DCONFIG_RET_SAMPLE_SEND_INTERVAL_S=2 \
	-DCONFIG_RET_RECEIPT_TIMEOUT_MS=5000 \
	>"$LOGS/build.log" 2>&1 || fail "build failed, see $LOGS/build.log"
EXE="$BUILD/ret_basic/zephyr/zephyr.exe"
[ -x "$EXE" ] || fail "no $EXE"

port_open && fail "port $PORT already in use; stop whatever is listening there"

echo "== start rnsd ($RNSD_CONFIG)"
uv run --quiet --project "$PEER_PROJECT" rnsd --config "$RNSD_CONFIG" -vv \
	>"$LOGS/rnsd.log" 2>&1 &
pids+=($!)
wait_for 30 "rnsd on port $PORT" port_open

run_scenario() {
	local name=$1 peer_args=() want_rc
	case $name in
	plain) want_rc=0 ;;
	ratchets) want_rc=0; peer_args=(--ratchets) ;;
	no-prove) want_rc=1; peer_args=(--no-prove) ;;
	*) fail "unknown scenario $name" ;;
	esac

	echo "== scenario $name"
	local peer_log="$LOGS/peer-$name.log" dev_log="$LOGS/device-$name.log"

	uv run --quiet --project "$PEER_PROJECT" "$PEER_PROJECT/peer.py" \
		--config "$RNSD_CONFIG" --announce-interval 3 "${peer_args[@]}" \
		>"$peer_log" 2>&1 &
	local peer=$!
	pids+=("$peer")
	wait_for 30 "peer ready" grep -q "^PEER READY" "$peer_log"
	local dest
	dest=$(awk '/^PEER READY/ {print $3; exit}' "$peer_log")

	# --seed-random: native_sim's test RNG otherwise starts from the same
	# seed every run, so ephemeral keys and IVs (and so packet hashes)
	# repeat, and rnsd drops the packets as duplicates of the last run's.
	local rc=0
	timeout 90 "$EXE" --seed-random >"$dev_log" 2>&1 || rc=$?
	kill "$peer" 2>/dev/null || true
	wait "$peer" 2>/dev/null || true

	[ $rc -ne 124 ] || fail "$name: device timed out, see $dev_log"
	[ $rc -eq "$want_rc" ] || fail "$name: device exit $rc, want $want_rc, see $dev_log"

	grep -q -- "-> CONNECTED" "$dev_log" || fail "$name: never connected"
	grep -q "ANNOUNCE VALID retclient.echo $dest" "$dev_log" ||
		fail "$name: no valid announce for $dest"
	if [ "$name" = ratchets ]; then
		grep -q "ANNOUNCE VALID retclient.echo $dest .*ratchet" "$dev_log" ||
			fail "$name: announce carried no ratchet"
	fi

	for n in $(seq 1 $COUNT); do
		grep -q "^RECEIVED hello #$n$" "$peer_log" ||
			fail "$name: peer did not decrypt hello #$n, see $peer_log"
		if [ "$want_rc" -eq 0 ]; then
			grep -q "PROOF VALID #$n " "$dev_log" || fail "$name: no valid proof for #$n"
		else
			grep -q "PROOF TIMEOUT #$n " "$dev_log" || fail "$name: no timeout for #$n"
		fi
	done

	local want_done=$COUNT
	[ "$want_rc" -eq 0 ] || want_done=0
	grep -q "DONE $want_done/$COUNT delivered" "$dev_log" ||
		fail "$name: want DONE $want_done/$COUNT, see $dev_log"

	# on_announce fires once per announce: the device can never report
	# more valid announces than the peer sent.
	local sent seen
	sent=$(grep -c "^ANNOUNCED$" "$peer_log" || true)
	seen=$(grep -c "ANNOUNCE VALID retclient.echo" "$dev_log" || true)
	[ "$seen" -le "$sent" ] || fail "$name: $seen announce callbacks for $sent announces"
	echo "   DONE $want_done/$COUNT delivered, $seen/$sent announces seen"
}

for s in "${scenarios[@]}"; do
	run_scenario "$s"
done

echo "PASS: ${scenarios[*]}"
