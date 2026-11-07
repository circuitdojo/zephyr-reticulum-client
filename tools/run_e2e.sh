#!/usr/bin/env bash
# End-to-end test of ret_basic and ret_lxmf against a real, isolated rnsd and
# the Python test peers.
#
# Announce-driven build (waits for an announce from retclient.echo):
#   plain     peer proves every packet              -> 3/3 delivered, exit 0
#   ratchets  peer announces with enforced ratchets -> 3/3 delivered, exit 0
#   no-prove  peer never proves                     -> 3 timeouts,    exit 1;
#             a destination that never proved does not trip the watchdog
#   echo      a link first (open, identify, "/echo" request, close), then the
#             peer answers each message to the client's own destination
#             (retclient.node), which decrypts and proves the reply
#             -> link response, 3/3 delivered both ways, both proved, exit 0
#
# Every device run shares one simulated flash file, so the client keeps its
# identity (address) across scenarios, as it would across reboots. echo
# runs after three earlier boots against the same rnsd: the client's
# announce only reaches the peer if its persisted announce clock moved
# forward over each reboot.
#
# ret_lxmf build (messages tools/rns_peer/lxmf_peer.py, a real LXMRouter):
#   lxmf      the device announces lxmf.delivery and sends 3 opportunistic
#             LXMF messages; the peer validates each signature and answers
#             "echo: ...", which the device verifies, delivers and answers
#             in turn -> 3/3 delivered, 3/3 echoes, replies validated, exit 0
#   store-forward  a local lxmd propagation node: the device boots and syncs
#             (nothing waiting), stops; tools/rns_peer/lxmf_send.py
#             deposits 12 PROPAGATED messages of 600 bytes and one of
#             5000 for it; the device boots again and its sync collects
#             the 12 in batches the 4 KB transfer limit cuts short, and
#             acknowledges them -> 12 delivered, only the 5000-byte one
#             (over the limit) left at the node, exit 0
#
# Known-hash build (sends to the peer's destination hash at once):
#   late      peer announced once before the device started: the only way
#             to learn the path is a path request   -> 6/6 delivered, exit 0
#   stall     peer proves #1 then goes silent: 3 timeouts from a destination
#             known to prove trip the receipt watchdog, which reconnects
#   bootdown  rnsd is down when the device boots and comes up a few seconds
#             later: connects fail and back off, then the client connects
#             and the later messages are delivered over a fresh path
#   restart   rnsd is restarted mid-run (new transport identity, empty path
#             table): the client reconnects, treats its paths as stale and
#             requests them again                   -> last message delivered
#
# Known-hash scenarios each start a fresh rnsd: rnsd drops repeat path
# requests for a destination for 45 s, which must not leak between them.
#
# Run from anywhere inside the west workspace with the Zephyr toolchain
# environment active (see AGENTS.md). Pass scenario names to run a subset.
# Logs land in build/ret_e2e-logs/.
set -euo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
RET=$(cd "$HERE/.." && pwd)
TOP=$(west topdir)
BUILD_NAME="$TOP/build/ret_e2e-name"
BUILD_HASH="$TOP/build/ret_e2e-hash"
BUILD_ECHO="$TOP/build/ret_e2e-echo"
BUILD_LXMF="$TOP/build/ret_e2e-lxmf"
BUILD_SF="$TOP/build/ret_e2e-sf"
# Not under a build dir: a pristine build wipes it.
LOGS="$TOP/build/ret_e2e-logs"
PEER_PROJECT="$HERE/rns_peer"
RNSD_CONFIG="$HERE/rnsd-test"
PORT=4243
COUNT_NAME=3
COUNT_HASH=6
COUNT_LXMF=3
COUNT_SF=12

scenarios=("$@")
[ ${#scenarios[@]} -gt 0 ] || scenarios=(plain ratchets no-prove echo lxmf store-forward late stall bootdown restart)

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

# Run the venv's binaries directly, not through `uv run` (or a shell
# function): then $! is the real process and killing it stops it, instead
# of orphaning a peer that stays attached to rnsd and disturbs later runs.
uv sync --quiet --project "$PEER_PROJECT"
PY="$PEER_PROJECT/.venv/bin/python"
RNSD="$PEER_PROJECT/.venv/bin/rnsd"

build() { # <dir> <count> [extra cmake args...]
	local dir=$1 count=$2
	shift 2
	echo "== build $(basename "$dir") ($count messages)"
	west build -b native_sim "$RET/samples/ret_basic" -d "$dir" -p --no-sysbuild -- \
		-DCONFIG_RET_SERVER_PORT=$PORT \
		-DCONFIG_RET_SAMPLE_MESSAGE_COUNT="$count" \
		-DCONFIG_RET_SAMPLE_SEND_INTERVAL_S=2 \
		-DCONFIG_RET_RECEIPT_TIMEOUT_MS=5000 \
		"$@" >"$LOGS/build-$(basename "$dir").log" 2>&1 ||
		fail "build failed, see $LOGS/build-$(basename "$dir").log"
	[ -x "$dir/zephyr/zephyr.exe" ] || fail "no $dir/zephyr/zephyr.exe"
}

RNSD_PID=
rnsd_log_n=0
start_rnsd() {
	rnsd_log_n=$((rnsd_log_n + 1))
	"$RNSD" --config "$RNSD_CONFIG" -vv >"$LOGS/rnsd-$rnsd_log_n.log" 2>&1 &
	RNSD_PID=$!
	pids+=("$RNSD_PID")
	wait_for 30 "rnsd on port $PORT" port_open
}

stop_rnsd() {
	kill "$RNSD_PID" 2>/dev/null || true
	wait "$RNSD_PID" 2>/dev/null || true
	wait_for 10 "rnsd to release port $PORT" bash -c "! (exec 3<>/dev/tcp/127.0.0.1/$PORT)"
}

needs() { # <scenario...>: true if any of them was selected
	local s w
	for s in "${scenarios[@]}"; do
		for w in "$@"; do
			[ "$s" = "$w" ] && return 0
		done
	done
	return 1
}

# Start clean: stale logs from an earlier run must not pass for this one's.
rm -rf "$LOGS"
mkdir -p "$LOGS"
FLASH="$LOGS/flash.bin"

needs plain ratchets no-prove && build "$BUILD_NAME" $COUNT_NAME
needs echo && build "$BUILD_ECHO" $COUNT_NAME -DCONFIG_RET_SAMPLE_EXPECT_REPLIES=y \
	-DCONFIG_RET_SAMPLE_LINK_TEST=y
if needs lxmf; then
	LXMF_PEER=$("$PY" "$PEER_PROJECT/lxmf_peer.py" --print-hash)
	echo "== build $(basename "$BUILD_LXMF") ($COUNT_LXMF messages)"
	west build -b native_sim "$RET/samples/ret_lxmf" -d "$BUILD_LXMF" -p --no-sysbuild -- \
		-DCONFIG_RET_SERVER_PORT=$PORT \
		-DCONFIG_RET_LXMF_SAMPLE_CONTACT=\""$LXMF_PEER"\" \
		-DCONFIG_RET_LXMF_SAMPLE_MESSAGE_COUNT=$COUNT_LXMF \
		-DCONFIG_RET_LXMF_SAMPLE_SEND_INTERVAL_S=2 \
		-DCONFIG_RET_RECEIPT_TIMEOUT_MS=5000 \
		>"$LOGS/build-$(basename "$BUILD_LXMF").log" 2>&1 ||
		fail "build failed, see $LOGS/build-$(basename "$BUILD_LXMF").log"
fi
if needs store-forward; then
	# A fresh node per run: its identity decides the hash the device
	# syncs with, and its message store starts empty.
	LXMD_DIR="$LOGS/lxmd"
	mkdir -p "$LXMD_DIR"
	cp "$HERE/lxmd-test/config" "$LXMD_DIR/config"
	NODE=$("$PY" "$PEER_PROJECT/lxmf_send.py" --make-node-identity "$LXMD_DIR/identity")
	echo "== build $(basename "$BUILD_SF") (propagation sync)"
	west build -b native_sim "$RET/samples/ret_lxmf" -d "$BUILD_SF" -p --no-sysbuild -- \
		-DCONFIG_RET_SERVER_PORT=$PORT \
		-DCONFIG_RET_LXMF_SAMPLE_PROPAGATION_NODE=\""$NODE"\" \
		-DCONFIG_RET_LXMF_SAMPLE_SYNC_AND_EXIT=y \
		>"$LOGS/build-$(basename "$BUILD_SF").log" 2>&1 ||
		fail "build failed, see $LOGS/build-$(basename "$BUILD_SF").log"
fi
if needs late stall bootdown restart; then
	DEST=$("$PY" "$PEER_PROJECT/peer.py" --print-hash)
	# The peer takes ~18 s to re-attach and re-announce after an rnsd
	# restart, during which every send is held: size the table for that.
	build "$BUILD_HASH" $COUNT_HASH -DCONFIG_RET_SAMPLE_DEST_HASH=\""$DEST"\" \
		-DCONFIG_RET_MAX_HELD_SENDS=8
fi

port_open && fail "port $PORT already in use; stop whatever is listening there"
pgrep -f "$PEER_PROJECT/((lxmf_peer|peer|lxmf_send)\.py|\.venv/bin/lxmd)" >/dev/null &&
	fail "a test peer is still running (pgrep -af peer.py); stop it first"

echo "== start rnsd ($RNSD_CONFIG)"
start_rnsd

start_peer() { # <log> [peer args...]
	local log=$1
	shift
	"$PY" "$PEER_PROJECT/peer.py" --config "$RNSD_CONFIG" "$@" >"$log" 2>&1 &
	PEER_PID=$!
	pids+=("$PEER_PID")
	wait_for 30 "peer ready" grep -q "^PEER READY" "$log"
	wait_for 10 "first announce" grep -q "^ANNOUNCED$" "$log"
}

stop_peer() {
	kill "$PEER_PID" 2>/dev/null || true
	wait "$PEER_PID" 2>/dev/null || true
}

# --seed-random: native_sim's test RNG otherwise starts from the same seed
# every run, so ephemeral keys and IVs (and so packet hashes) repeat, and
# rnsd drops the packets as duplicates of an earlier run's.
run_device() { # <exe> <log>  (sets RC)
	RC=0
	timeout 120 "$1" --seed-random --flash="$FLASH" >"$2" 2>&1 || RC=$?
	[ $RC -ne 124 ] || fail "device timed out, see $2"
}

check_messages() { # <name> <dev_log> <peer_log> <count> <proof|timeout> [first]
	local name=$1 dev=$2 peerlog=$3 count=$4 want=$5 first=${6:-1} n
	for n in $(seq "$first" "$count"); do
		grep -q "^RECEIVED hello #$n$" "$peerlog" ||
			fail "$name: peer did not decrypt hello #$n, see $peerlog"
		if [ "$want" = proof ]; then
			grep -q "PROOF VALID #$n " "$dev" || fail "$name: no valid proof for #$n, see $dev"
		else
			grep -q "PROOF TIMEOUT #$n " "$dev" || fail "$name: no timeout for #$n, see $dev"
		fi
	done
}

scenario_announced() { # plain | ratchets | no-prove
	local name=$1 peer_args=() want_rc=0 want=proof
	case $name in
	ratchets) peer_args=(--ratchets) ;;
	no-prove) peer_args=(--no-prove) want_rc=1 want=timeout ;;
	esac
	local peer_log="$LOGS/peer-$name.log" dev_log="$LOGS/device-$name.log"

	start_peer "$peer_log" --announce-interval 3 "${peer_args[@]}"
	local dest
	dest=$(awk '/^PEER READY/ {print $3; exit}' "$peer_log")
	run_device "$BUILD_NAME/zephyr/zephyr.exe" "$dev_log"
	stop_peer

	[ $RC -eq $want_rc ] || fail "$name: device exit $RC, want $want_rc, see $dev_log"
	grep -q -- "-> CONNECTED" "$dev_log" || fail "$name: never connected"
	grep -q "ANNOUNCE VALID retclient.echo $dest" "$dev_log" ||
		fail "$name: no valid announce for $dest"
	if [ "$name" = ratchets ]; then
		grep -q "ANNOUNCE VALID retclient.echo $dest .*ratchet" "$dev_log" ||
			fail "$name: announce carried no ratchet"
	fi
	if [ "$name" = no-prove ]; then
		# Never proved, so its timeouts say nothing about the link.
		! grep -q "receipts in a row timed out" "$dev_log" ||
			fail "$name: watchdog reconnected over a destination that never proves"
	fi
	check_messages "$name" "$dev_log" "$peer_log" $COUNT_NAME $want

	local want_done=$COUNT_NAME
	[ $want_rc -eq 0 ] || want_done=0
	grep -q "DONE $want_done/$COUNT_NAME delivered" "$dev_log" ||
		fail "$name: want DONE $want_done/$COUNT_NAME, see $dev_log"

	# on_announce fires once per announce: the device can never report
	# more valid announces than the peer sent (no path requests here).
	local sent seen
	sent=$(grep -c "^ANNOUNCED$" "$peer_log" || true)
	seen=$(grep -c "ANNOUNCE VALID retclient.echo" "$dev_log" || true)
	[ "$seen" -le "$sent" ] || fail "$name: $seen announce callbacks for $sent announces"
	echo "   DONE $want_done/$COUNT_NAME delivered, $seen/$sent announces seen"
}

scenario_echo() {
	local peer_log="$LOGS/peer-echo.log" dev_log="$LOGS/device-echo.log" n

	start_peer "$peer_log" --announce-interval 3 --reply
	run_device "$BUILD_ECHO/zephyr/zephyr.exe" "$dev_log"
	# Give the peer a moment to log the client's last proof.
	sleep 1
	stop_peer

	[ $RC -eq 0 ] || fail "echo: device exit $RC, want 0, see $dev_log"
	local own
	own=$(awk '/OWN ADDRESS/ {print $NF; exit}' "$dev_log" | tr -d '\r' | sed 's/\x1b\[[0-9;]*m//g')
	[ -n "$own" ] || fail "echo: device reported no address"
	grep -q "^CLIENT ANNOUNCE $own$" "$peer_log" ||
		fail "echo: peer never received the client's announce for $own, see $peer_log"
	check_messages echo "$dev_log" "$peer_log" $COUNT_NAME proof
	for n in $(seq 1 $COUNT_NAME); do
		grep -q "RECEIVED echo: hello #$n" "$dev_log" ||
			fail "echo: device did not receive the reply to #$n, see $dev_log"
		grep -q "^REPLY PROVED echo: hello #$n$" "$peer_log" ||
			fail "echo: peer got no proof from the client for reply #$n, see $peer_log"
	done
	# The link: established, identified with the client's identity (the
	# hash the peer saw must be the one it echoed back), request, close.
	grep -q "LINK ACTIVE" "$dev_log" || fail "echo: link never became active, see $dev_log"
	grep -q "^LINK ESTABLISHED$" "$peer_log" || fail "echo: peer saw no link"
	local ident
	ident=$(awk '/^LINK IDENTIFIED/ {print $3; exit}' "$peer_log")
	[ -n "$ident" ] || fail "echo: peer saw no identify, see $peer_log"
	grep -q "LINK RESPONSE pong:ping:$ident" "$dev_log" ||
		fail "echo: wrong or missing link response, see $dev_log"
	# A response larger than a packet: a resource, proved; a compressed
	# one is refused (RESOURCE_RCL).
	grep -q "LINK BIG RESPONSE 4000 bytes" "$dev_log" ||
		fail "echo: large response (resource) not received intact, see $dev_log"
	grep -q "^RESOURCE PROVED" "$peer_log" ||
		fail "echo: peer saw no valid resource proof, see $peer_log"
	grep -q "LINK COMPRESSED REFUSED" "$dev_log" ||
		fail "echo: compressed resource not refused, see $dev_log"
	grep -q "^RESOURCE REFUSED" "$peer_log" ||
		fail "echo: peer saw no resource refusal, see $peer_log"
	grep -q "LINK RESPONSE AFTER IDLE pong:ping:$ident" "$dev_log" ||
		fail "echo: link did not survive 15 s idle (keepalives), see $dev_log"
	grep -q "LINK CLOSED" "$dev_log" || fail "echo: device did not close the link"
	grep -q "^LINK CLOSED$" "$peer_log" || fail "echo: peer did not see the link close"

	grep -q "DONE $COUNT_NAME/$COUNT_NAME delivered, $COUNT_NAME/$COUNT_NAME replies" "$dev_log" ||
		fail "echo: want DONE $COUNT_NAME/$COUNT_NAME, $COUNT_NAME/$COUNT_NAME replies"
	echo "   $COUNT_NAME/$COUNT_NAME each way, proved both ways (client $own)"
}

scenario_lxmf() {
	local peer_log="$LOGS/peer-lxmf.log" dev_log="$LOGS/device-lxmf.log" n

	"$PY" "$PEER_PROJECT/lxmf_peer.py" --config "$RNSD_CONFIG" --announce-interval 3 \
		>"$peer_log" 2>&1 &
	PEER_PID=$!
	pids+=("$PEER_PID")
	wait_for 30 "LXMF peer ready" grep -q "^PEER READY" "$peer_log"
	wait_for 10 "first announce" grep -q "^ANNOUNCED$" "$peer_log"
	run_device "$BUILD_LXMF/zephyr/zephyr.exe" "$dev_log"
	# The device's last replies are in flight as it exits.
	sleep 2
	stop_peer

	[ $RC -eq 0 ] || fail "lxmf: device exit $RC, want 0, see $dev_log"
	local own
	own=$(awk '/LXMF ADDRESS/ {print $(NF-1); exit}' "$dev_log" | tr -d '\r' |
		sed 's/\x1b\[[0-9;]*m//g')
	[ -n "$own" ] || fail "lxmf: device reported no address"
	# The announce carries LXMF app_data: display name, no stamp cost.
	grep -q "^LXMF DEVICE ANNOUNCE $own ret-lxmf stamp_cost=None$" "$peer_log" ||
		fail "lxmf: peer did not parse the device's LXMF announce, see $peer_log"
	for n in $(seq 1 $COUNT_LXMF); do
		grep -q "^LXMF RECEIVED validated $own |hello #$n$" "$peer_log" ||
			fail "lxmf: peer did not validate hello #$n, see $peer_log"
		grep -q "LXMF DELIVERED #$n " "$dev_log" ||
			fail "lxmf: no delivery proof for #$n, see $dev_log"
		grep -q "LXMF RECEIVED verified from $LXMF_PEER: |echo: hello #$n" "$dev_log" ||
			fail "lxmf: device did not verify echo #$n, see $dev_log"
		grep -q "^REPLY DELIVERED echo: hello #$n$" "$peer_log" ||
			fail "lxmf: device did not prove echo #$n, see $peer_log"
		grep -q "^LXMF RECEIVED validated $own |re: echo: hello #$n$" "$peer_log" ||
			fail "lxmf: peer did not validate the device's reply to #$n, see $peer_log"
	done
	grep -q "DONE $COUNT_LXMF/$COUNT_LXMF delivered, $COUNT_LXMF/$COUNT_LXMF echoes" "$dev_log" ||
		fail "lxmf: want DONE $COUNT_LXMF/$COUNT_LXMF, see $dev_log"
	echo "   $COUNT_LXMF/$COUNT_LXMF each way, signatures validated both ways (device $own)"
}

scenario_store_forward() {
	local lxmd_log="$LOGS/lxmd.log" send_log="$LOGS/sender-sf.log" go="$LOGS/sf-go"
	local dev1="$LOGS/device-sf-1.log" dev2="$LOGS/device-sf-2.log" n

	# Unbuffered: its log is how we know it is up.
	PYTHONUNBUFFERED=1 "$PEER_PROJECT/.venv/bin/lxmd" --config "$LXMD_DIR" --rnsconfig "$RNSD_CONFIG" -p \
		>"$lxmd_log" 2>&1 &
	local lxmd_pid=$!
	pids+=("$lxmd_pid")
	wait_for 30 "lxmd to start" grep -q "$NODE" "$lxmd_log"

	"$PY" "$PEER_PROJECT/lxmf_send.py" --config "$RNSD_CONFIG" --node "$NODE" \
		--to-name ret-lxmf --count $COUNT_SF --size 600 --big 5000 --go-file "$go" \
		>"$send_log" 2>&1 &
	local send_pid=$!
	pids+=("$send_pid")
	wait_for 30 "sender ready" grep -q "^SENDER READY" "$send_log"
	local sender
	sender=$(awk '/^SENDER READY/ {print $3; exit}' "$send_log")

	# Boot 1: nothing waiting. The sender learns the device's key from
	# its announce.
	run_device "$BUILD_SF/zephyr/zephyr.exe" "$dev1"
	[ $RC -eq 0 ] || fail "store-forward: first sync failed (exit $RC), see $dev1"
	grep -q "SYNC DONE 0 0" "$dev1" || fail "store-forward: first sync not empty, see $dev1"

	# Offline: deposit at the node.
	wait_for 30 "sender to see the device" grep -q "^TARGET" "$send_log"
	touch "$go"
	wait "$send_pid" || fail "store-forward: deposit failed, see $send_log"
	for n in $(seq 1 $COUNT_SF); do
		grep -q "^DEPOSITED stored #$n$" "$send_log" ||
			fail "store-forward: stored #$n not deposited, see $send_log"
	done
	grep -q "^DEPOSITED big$" "$send_log" || fail "store-forward: big not deposited"
	local store="$LXMD_DIR/storage/lxmf/messagestore" held
	[ -d "$store" ] || fail "store-forward: no lxmd message store at $store"
	held=$(find "$store" -type f | wc -l)
	[ "$held" -eq $((COUNT_SF + 1)) ] ||
		fail "store-forward: node holds $held messages, want $((COUNT_SF + 1))"

	# Boot 2: the sync collects them.
	run_device "$BUILD_SF/zephyr/zephyr.exe" "$dev2"
	kill "$lxmd_pid" 2>/dev/null || true
	wait "$lxmd_pid" 2>/dev/null || true

	[ $RC -eq 0 ] || fail "store-forward: second sync failed (exit $RC), see $dev2"
	for n in $(seq 1 $COUNT_SF); do
		grep -q "LXMF RECEIVED [A-Za-z]* from $sender: |stored #$n\b" "$dev2" ||
			fail "store-forward: stored #$n not delivered, see $dev2"
	done
	grep -q "SYNC DONE 0 $COUNT_SF" "$dev2" ||
		fail "store-forward: want SYNC DONE 0 $COUNT_SF, see $dev2"
	grep -q "1 propagated message(s) exceed RET_LXMF_SYNC_LIMIT_KB" "$dev2" ||
		fail "store-forward: the oversized message was not reported, see $dev2"
	! grep -q "LXMF RECEIVED .*|big" "$dev2" ||
		fail "store-forward: the oversized message was delivered"
	# Acknowledged: the node deleted them, all but the oversized one.
	local left
	left=$(find "$store" -type f | wc -l)
	[ "$left" -eq 1 ] || fail "store-forward: $left message(s) at the node, want 1"
	local unverified
	unverified=$(grep -c "LXMF RECEIVED UNVERIFIED" "$dev2" || true)
	echo "   $COUNT_SF/$COUNT_SF collected and acknowledged, oversized one left ($unverified unverified: sender unseen)"
}

fresh_rnsd() {
	stop_rnsd
	start_rnsd
}

scenario_late() {
	local peer_log="$LOGS/peer-late.log" dev_log="$LOGS/device-late.log"

	fresh_rnsd
	# One announce, long before the device connects; rnsd will not replay it.
	start_peer "$peer_log" --announce-interval 3600
	sleep 2
	run_device "$BUILD_HASH/zephyr/zephyr.exe" "$dev_log"
	stop_peer

	[ $RC -eq 0 ] || fail "late: device exit $RC, want 0, see $dev_log"
	grep -q "path request for" "$dev_log" || fail "late: no path request sent"
	check_messages late "$dev_log" "$peer_log" $COUNT_HASH proof
	echo "   DONE $COUNT_HASH/$COUNT_HASH delivered via path request"
}

scenario_stall() {
	local peer_log="$LOGS/peer-stall.log" dev_log="$LOGS/device-stall.log"

	fresh_rnsd
	start_peer "$peer_log" --announce-interval 3 --stop-proving-after 1
	run_device "$BUILD_HASH/zephyr/zephyr.exe" "$dev_log"
	stop_peer

	grep -q "PROOF VALID #1 " "$dev_log" || fail "stall: no proof for #1"
	for n in 2 3 4; do
		grep -q "PROOF TIMEOUT #$n " "$dev_log" || fail "stall: no timeout for #$n"
	done
	grep -q "3 receipts in a row timed out, reconnecting" "$dev_log" ||
		fail "stall: watchdog did not reconnect, see $dev_log"
	local connects
	connects=$(grep -c -- "-> CONNECTED" "$dev_log" || true)
	[ "$connects" -ge 2 ] || fail "stall: did not reconnect after the watchdog"
	echo "   watchdog reconnected after 3 timeouts"
}

scenario_bootdown() {
	local peer_log="$LOGS/peer-bootdown.log" dev_log="$LOGS/device-bootdown.log"

	stop_rnsd
	RC=0
	timeout 120 "$BUILD_HASH/zephyr/zephyr.exe" --seed-random --flash="$FLASH" \
		>"$dev_log" 2>&1 &
	local dev=$!
	pids+=("$dev")

	wait_for 30 "a failed connect" grep -q "connect failed" "$dev_log"
	start_rnsd
	start_peer "$peer_log" --announce-interval 3600

	wait "$dev" || RC=$?
	stop_peer
	[ $RC -ne 124 ] || fail "bootdown: device timed out, see $dev_log"

	grep -q -- "-> CONNECTED" "$dev_log" || fail "bootdown: never connected once rnsd was up"
	check_messages bootdown "$dev_log" "$peer_log" $COUNT_HASH proof $COUNT_HASH
	local done_line
	done_line=$(grep -o "DONE [0-9]*/$COUNT_HASH delivered" "$dev_log") ||
		fail "bootdown: no DONE line, see $dev_log"
	echo "   $done_line (sends while rnsd was down fail)"
}

scenario_restart() {
	local peer_log="$LOGS/peer-restart.log" dev_log="$LOGS/device-restart.log"

	fresh_rnsd
	start_peer "$peer_log" --announce-interval 3600
	RC=0
	timeout 120 "$BUILD_HASH/zephyr/zephyr.exe" --seed-random --flash="$FLASH" \
		>"$dev_log" 2>&1 &
	local dev=$!
	pids+=("$dev")

	wait_for 60 "first proof" grep -q "PROOF VALID #1 " "$dev_log"
	echo "   restarting rnsd"
	stop_rnsd
	start_rnsd

	wait "$dev" || RC=$?
	stop_peer
	[ $RC -ne 124 ] || fail "restart: device timed out, see $dev_log"

	grep -q -- "-> RECONNECTING" "$dev_log" || fail "restart: never noticed rnsd going away"
	local connects
	connects=$(grep -c -- "-> CONNECTED" "$dev_log" || true)
	[ "$connects" -ge 2 ] || fail "restart: did not reconnect, see $dev_log"
	# The last message is sent well after the restart, so it can only be
	# delivered over a path learned again after reconnecting.
	check_messages restart "$dev_log" "$peer_log" $COUNT_HASH proof $COUNT_HASH
	local done_line
	done_line=$(grep -o "DONE [0-9]*/$COUNT_HASH delivered" "$dev_log") ||
		fail "restart: no DONE line, see $dev_log"
	echo "   $done_line (messages in flight during the restart may be lost)"
}

for s in "${scenarios[@]}"; do
	echo "== scenario $s"
	case $s in
	plain | ratchets | no-prove) scenario_announced "$s" ;;
	echo) scenario_echo ;;
	lxmf) scenario_lxmf ;;
	store-forward) scenario_store_forward ;;
	late) scenario_late ;;
	stall) scenario_stall ;;
	bootdown) scenario_bootdown ;;
	restart) scenario_restart ;;
	*) fail "unknown scenario $s" ;;
	esac
done

echo "PASS: ${scenarios[*]}"
