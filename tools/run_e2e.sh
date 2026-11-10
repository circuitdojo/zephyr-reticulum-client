#!/usr/bin/env bash
# End-to-end test of ret_basic and ret_lxmf against a real, isolated rnsd and
# the Python test peers.
#
# Announce-driven build (waits for an announce from retclient.echo):
#   plain     peer proves every packet              -> 3/3 delivered, exit 0
#   ratchets  peer announces with enforced ratchets -> 3/3 delivered, exit 0
#   no-prove  peer never proves                     -> 3 timeouts,    exit 1;
#             a destination that never proved does not trip the watchdog
#   ifac      the same as plain, on rnsd's protected interface (port 4244,
#             network_name + passphrase): 3/3 delivered; then a device with
#             the wrong passphrase hears nothing (it drops rnsd's packets)
#             and gets nothing through
#   echo      a link first (open, identify, "/echo" request, close), then the
#             peer answers each message to the client's own destination
#             (retclient.node), which decrypts and proves the reply; the
#             peer also opens its own link to the device (responder side):
#             4 packets proved, one after 15 s on answered keepalives
#             -> link response, 3/3 delivered both ways, both proved, exit 0
#   lora-gateway  samples/ret_lora_gateway, a transport node with a simulated
#             LoRa radio (tools/rns_peer/air.py) and a TCP uplink to a stock
#             rnsd (tools/rnsd-test-lora), with RNS LoRa peers on the air:
#             a device on the hub reaches a LoRa peer (DATA, proofs, replies,
#             a link and a resource in split frames); two LoRa hops through
#             a repeater; two LoRa nodes that cannot hear each other talk
#             through the gateway with the hub down; the gateway reboots
#             (same identity, paths from its flash) and the restarted hub
#             restores its paths through it (tunnel); a LoRa node discovers
#             a destination the gateway never heard of; and an IFAC uplink
#             with the right passphrase gets through, a wrong one is ignored
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
#             in turn -> 3/3 delivered, 3/3 echoes, replies validated, exit 0;
#             the peer saw the device's ratchet in its announce, so the
#             echoes it encrypts to the device use that ratchet
#   lxmf-direct  the same, the peer answering DIRECT (over a link it opens
#             to the device, which is the responder), plus a 3000-byte
#             message (a Resource: delivered) and a 12000-byte one (over
#             RET_RESOURCE_MAX_SIZE: refused, LXMF marks it rejected)
#   chat      ret_chat, driven through its shell on stdin (--uart_stdinout):
#             it hears the peer's announce ('heard'), names it ('contact
#             add'), sends to it by name (opportunistic) and gets the
#             peer's echo into its inbox ('msg read'); a 451-byte message
#             goes DIRECT as a Resource and its long echo arrives DIRECT;
#             after a reboot the contact is still there -> all checked
#   store-forward  a local lxmd propagation node: the device boots and syncs
#             (nothing waiting), stops; tools/rns_peer/lxmf_send.py
#             deposits 12 PROPAGATED messages of 600 bytes and one of
#             5000 for it; the device boots again and its sync collects
#             the 12 in batches the 4 KB transfer limit cuts short, and
#             acknowledges them -> 12 delivered, only the 5000-byte one
#             (over the limit) left at the node, exit 0. They are
#             encrypted to the device's announced ratchet. Those arrive
#             unverified (sender unseen); the device asks for the
#             sender's path and keeps its key, so on a third boot a new
#             message verifies with nothing but the kept key.
#
# ret_lxmf_sleep build (the sleepy node):
#   sleep     3 wakes, 30 s apart: each resumes, reconnects, announces,
#             syncs and suspends (socket closed). Messages deposited while
#             it sleeps arrive at the next wake -> syncs of 0, 2, 1, the
#             last one verified, exit 0. Built with a 20 s ratchet
#             interval, every wake rotates: the last message, encrypted
#             to wake 2's ratchet, still decrypts at wake 3
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
BUILD_SLEEP="$TOP/build/ret_e2e-sleep"
BUILD_CHAT="$TOP/build/ret_e2e-chat"
BUILD_IFAC="$TOP/build/ret_e2e-ifac"
BUILD_IFAC_BAD="$TOP/build/ret_e2e-ifac-bad"
BUILD_GW="$TOP/build/ret_e2e-gw"
BUILD_GW_IFAC="$TOP/build/ret_e2e-gw-ifac"
BUILD_GW_IFAC_BAD="$TOP/build/ret_e2e-gw-ifac-bad"
BUILD_GW_DEV="$TOP/build/ret_e2e-gw-dev"
# Not under a build dir: a pristine build wipes it.
LOGS="$TOP/build/ret_e2e-logs"
PEER_PROJECT="$HERE/rns_peer"
RNSD_CONFIG="$HERE/rnsd-test"
PORT=4243
# rnsd-test's protected interface, and its network name and passphrase.
IFAC_PORT=4244
IFAC_NETNAME="ret-test"
IFAC_PASSPHRASE="correct horse battery staple"
# tools/rnsd-test-lora: the hub for lora-gateway, open and with IFAC.
LORA_CONFIG="$HERE/rnsd-test-lora"
LORA_TCP_PORT=4245
LORA_IFAC_PORT=4247
# UDP ports of the simulated air and its radios.
AIR_PORT=5100
AIR_GW=5101
AIR_N1=5102
AIR_REPEATER=5103
AIR_N2=5104
AIR_N3=5105
COUNT_NAME=3
COUNT_HASH=6
COUNT_LXMF=3
COUNT_SF=12

scenarios=("$@")
[ ${#scenarios[@]} -gt 0 ] || scenarios=(plain ratchets no-prove ifac lora-gateway echo lxmf lxmf-direct chat store-forward sleep late stall bootdown restart)

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
	# Unbuffered: rnsd is killed, not stopped, and its log is checked.
	PYTHONUNBUFFERED=1 "$RNSD" --config "$RNSD_CONFIG" -vv >"$LOGS/rnsd-$rnsd_log_n.log" 2>&1 &
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
if needs ifac; then
	build "$BUILD_IFAC" $COUNT_NAME -DCONFIG_RET_SERVER_PORT=$IFAC_PORT -DCONFIG_RET_IFAC=y \
		-DCONFIG_RET_IFAC_NETWORK_NAME=\""$IFAC_NETNAME"\" \
		-DCONFIG_RET_IFAC_PASSPHRASE=\""$IFAC_PASSPHRASE"\"
	# Knows the peer's hash, so it transmits (path requests) at once.
	build "$BUILD_IFAC_BAD" $COUNT_NAME -DCONFIG_RET_SERVER_PORT=$IFAC_PORT -DCONFIG_RET_IFAC=y \
		-DCONFIG_RET_IFAC_NETWORK_NAME=\""$IFAC_NETNAME"\" \
		-DCONFIG_RET_IFAC_PASSPHRASE=\"wrong\" \
		-DCONFIG_RET_SAMPLE_DEST_HASH=\""$("$PY" "$PEER_PROJECT/peer.py" --print-hash)"\"
fi
if needs lora-gateway; then
	# Identities first: the device and the senders are told who to reach.
	for n in n1 n2 n3 hub; do
		mkdir -p "$LOGS/air-$n"
	done
	LORA_N1=$("$PY" "$PEER_PROJECT/peer.py" --identity "$LOGS/air-n1/identity" --print-hash)
	LORA_N2=$("$PY" "$PEER_PROJECT/peer.py" --identity "$LOGS/air-n2/identity" --print-hash)
	LORA_X=$("$PY" "$PEER_PROJECT/peer.py" --identity "$LOGS/air-hub/x-identity" --print-hash)
	build_gateway() { # <dir> <hub port> [extra cmake args...]
		local dir=$1 port=$2
		shift 2
		echo "== build $(basename "$dir") (LoRa gateway)"
		west build -b native_sim "$RET/samples/ret_lora_gateway" -d "$dir" -p --no-sysbuild -- \
			-DCONFIG_RET_GATEWAY_PORT="$port" \
			-DCONFIG_RET_GATEWAY_RECONNECT_MAX_S=2 \
			-DCONFIG_RET_LORA_BACKOFF_MS=100 \
			-DCONFIG_RET_LORA_SIM_AIR_PORT=$AIR_PORT \
			-DCONFIG_RET_LORA_SIM_LOCAL_PORT=$AIR_GW \
			"$@" >"$LOGS/build-$(basename "$dir").log" 2>&1 ||
			fail "build failed, see $LOGS/build-$(basename "$dir").log"
		[ -x "$dir/zephyr/zephyr.exe" ] || fail "no $dir/zephyr/zephyr.exe"
	}
	build_gateway "$BUILD_GW" $LORA_TCP_PORT
	build_gateway "$BUILD_GW_IFAC" $LORA_IFAC_PORT \
		-DCONFIG_RET_GATEWAY_IFAC_NETWORK_NAME=\""$IFAC_NETNAME"\" \
		-DCONFIG_RET_GATEWAY_IFAC_PASSPHRASE=\""$IFAC_PASSPHRASE"\"
	build_gateway "$BUILD_GW_IFAC_BAD" $LORA_IFAC_PORT \
		-DCONFIG_RET_GATEWAY_IFAC_NETWORK_NAME=\""$IFAC_NETNAME"\" \
		-DCONFIG_RET_GATEWAY_IFAC_PASSPHRASE=\"wrong\"
	# Sends to the first retclient.echo it hears announce: n1.
	build "$BUILD_GW_DEV" $COUNT_NAME -DCONFIG_RET_SERVER_PORT=$LORA_TCP_PORT \
		-DCONFIG_RET_SAMPLE_EXPECT_REPLIES=y -DCONFIG_RET_SAMPLE_REPLY_WAIT_S=30 \
		-DCONFIG_RET_SAMPLE_LINK_TEST=y
fi
needs echo && build "$BUILD_ECHO" $COUNT_NAME -DCONFIG_RET_SAMPLE_EXPECT_REPLIES=y \
	-DCONFIG_RET_SAMPLE_LINK_TEST=y
if needs lxmf lxmf-direct chat; then
	LXMF_PEER=$("$PY" "$PEER_PROJECT/lxmf_peer.py" --print-hash)
fi
if needs chat; then
	echo "== build $(basename "$BUILD_CHAT") (shell)"
	west build -b native_sim "$RET/samples/ret_chat" -d "$BUILD_CHAT" -p --no-sysbuild -- \
		-DCONFIG_RET_SERVER_PORT=$PORT \
		-DCONFIG_RET_RECEIPT_TIMEOUT_MS=5000 \
		>"$LOGS/build-$(basename "$BUILD_CHAT").log" 2>&1 ||
		fail "build failed, see $LOGS/build-$(basename "$BUILD_CHAT").log"
fi
if needs lxmf lxmf-direct; then
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
if needs store-forward sleep; then
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
	echo "== build $(basename "$BUILD_SLEEP") (sleepy node)"
	west build -b native_sim "$RET/samples/ret_lxmf_sleep" -d "$BUILD_SLEEP" -p --no-sysbuild -- \
		-DCONFIG_RET_SERVER_PORT=$PORT \
		-DCONFIG_RET_SLEEP_PROPAGATION_NODE=\""$NODE"\" \
		-DCONFIG_RET_SLEEP_CYCLES=3 \
		-DCONFIG_RET_SLEEP_INTERVAL_S=30 \
		-DCONFIG_RET_SLEEP_WAKE_TIMEOUT_S=30 \
		-DCONFIG_RET_RECEIPT_TIMEOUT_MS=5000 \
		-DCONFIG_RET_RATCHET_INTERVAL_S=20 \
		>"$LOGS/build-$(basename "$BUILD_SLEEP").log" 2>&1 ||
		fail "build failed, see $LOGS/build-$(basename "$BUILD_SLEEP").log"
fi
if needs late stall bootdown restart; then
	DEST=$("$PY" "$PEER_PROJECT/peer.py" --print-hash)
	# The peer takes ~18 s to re-attach and re-announce after an rnsd
	# restart, during which every send is held: size the table for that.
	build "$BUILD_HASH" $COUNT_HASH -DCONFIG_RET_SAMPLE_DEST_HASH=\""$DEST"\" \
		-DCONFIG_RET_MAX_HELD_SENDS=8
fi

port_open && fail "port $PORT already in use; stop whatever is listening there"
# Only tools attached to the test rnsd (tools/rnsd-test) disturb a run;
# a hardware hub on tools/rnsd-hw (peer.py, lxmd) can stay up.
pgrep -af "$PEER_PROJECT/((lxmf_peer|peer|lxmf_send)\.py|\.venv/bin/lxmd)" |
	grep -qF -- "$RNSD_CONFIG" &&
	fail "a test peer is still attached to $RNSD_CONFIG (pgrep -af rnsd-test); stop it first"

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

# The device's newest ratchet id: the last one it logged (loaded at boot,
# or rotated to).
device_ratchet() { # <dev_log>
	grep -o "\(new\|current\) ratchet [0-9a-f]*" "$1" | tail -1 | awk '{print $3}'
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

scenario_ifac() {
	local peer_log="$LOGS/peer-ifac.log" dev_log="$LOGS/device-ifac.log"
	local bad_log="$LOGS/device-ifac-bad.log" dest

	start_peer "$peer_log" --announce-interval 3
	dest=$(awk '/^PEER READY/ {print $3; exit}' "$peer_log")
	run_device "$BUILD_IFAC/zephyr/zephyr.exe" "$dev_log"
	[ $RC -eq 0 ] || fail "ifac: device exit $RC, want 0, see $dev_log"
	grep -q 'IFAC on: with network name, with passphrase, 16-byte codes' "$dev_log" ||
		fail "ifac: IFAC not on, see $dev_log"
	! grep -q "ret-test\|correct horse" "$dev_log" ||
		fail "ifac: the network name or passphrase was logged, see $dev_log"
	grep -q "ANNOUNCE VALID retclient.echo $dest" "$dev_log" ||
		fail "ifac: no valid announce through the protected interface"
	check_messages ifac "$dev_log" "$peer_log" $COUNT_NAME proof
	! grep -q "access code" "$dev_log" || fail "ifac: packets dropped, see $dev_log"

	# The wrong passphrase: the TCP connection opens, but neither side
	# accepts the other's packets. The build knows the peer's hash, so it
	# sends (path requests) and rnsd must refuse them; it never gets a
	# path, so it runs until stopped.
	local before rnsd_log violations
	rnsd_log="$LOGS/rnsd-$rnsd_log_n.log"
	violations=$(grep -c "IFAC violation" "$rnsd_log" || true)
	before=$(grep -c "^RECEIVED" "$peer_log" || true)
	RC=0
	timeout 20 "$BUILD_IFAC_BAD/zephyr/zephyr.exe" --seed-random --flash="$FLASH" \
		>"$bad_log" 2>&1 || RC=$?
	stop_peer
	[ $RC -eq 124 ] || fail "ifac: wrong-passphrase device exit $RC, want a timeout, see $bad_log"
	grep -q "dropping packets with a wrong access code" "$bad_log" ||
		fail "ifac: the wrong-passphrase device did not drop rnsd's packets, see $bad_log"
	! grep -q "ANNOUNCE VALID" "$bad_log" ||
		fail "ifac: the wrong-passphrase device accepted an announce, see $bad_log"
	[ "$(grep -c "^RECEIVED" "$peer_log" || true)" -eq "$before" ] ||
		fail "ifac: something got through with the wrong passphrase, see $peer_log"
	grep -q "path request for" "$bad_log" ||
		fail "ifac: the wrong-passphrase device sent nothing, see $bad_log"
	[ "$(grep -c "IFAC violation" "$rnsd_log" || true)" -gt "$violations" ] ||
		fail "ifac: rnsd did not refuse the wrong-passphrase device, see $rnsd_log"
	echo "   $COUNT_NAME/$COUNT_NAME delivered on the protected interface;"
	echo "   the wrong passphrase heard nothing and got nothing through"
}

scenario_echo() {
	local peer_log="$LOGS/peer-echo.log" dev_log="$LOGS/device-echo.log" n

	start_peer "$peer_log" --announce-interval 3 --reply --link-client 3
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

	# The peer's link to the device (responder side), while the device's
	# own link and sends run: data proved, kept up by answered keepalives.
	grep -q "^CLIENT LINK ACTIVE mtu 500$" "$peer_log" ||
		fail "echo: the peer's link to the device never came up, see $peer_log"
	for n in 1 2 3 4; do
		grep -q "^CLIENT LINK DATA PROVED $n$" "$peer_log" ||
			fail "echo: link packet $n not proved by the device, see $peer_log"
		grep -q "RECEIVED link #$n" "$dev_log" ||
			fail "echo: device did not deliver link packet $n, see $dev_log"
	done
	grep -q "inbound link closed by peer" "$dev_log" ||
		fail "echo: device did not see the peer close its link, see $dev_log"
	grep -q "DONE $COUNT_NAME/$COUNT_NAME delivered, $COUNT_NAME/$COUNT_NAME replies" "$dev_log" ||
		fail "echo: want DONE $COUNT_NAME/$COUNT_NAME, $COUNT_NAME/$COUNT_NAME replies"
	echo "   $COUNT_NAME/$COUNT_NAME each way, proved both ways (client $own)"
}

scenario_lxmf() { # [direct]
	local mode=${1:-opportunistic} name=lxmf peer_args=()
	if [ "$mode" = direct ]; then
		name=lxmf-direct
		peer_args=(--reply-method direct --mid-reply 310 --big-reply 3000 --huge-reply 12000)
	fi
	local peer_log="$LOGS/peer-$name.log" dev_log="$LOGS/device-$name.log" n

	"$PY" "$PEER_PROJECT/lxmf_peer.py" --config "$RNSD_CONFIG" --announce-interval 3 \
		"${peer_args[@]}" >"$peer_log" 2>&1 &
	PEER_PID=$!
	pids+=("$PEER_PID")
	wait_for 30 "LXMF peer ready" grep -q "^PEER READY" "$peer_log"
	wait_for 10 "first announce" grep -q "^ANNOUNCED$" "$peer_log"
	run_device "$BUILD_LXMF/zephyr/zephyr.exe" "$dev_log"
	# The device's last replies are in flight as it exits.
	sleep 2
	stop_peer

	[ $RC -eq 0 ] || fail "$name: device exit $RC, want 0, see $dev_log"
	local own
	own=$(awk '/LXMF ADDRESS/ {print $(NF-1); exit}' "$dev_log" | tr -d '\r' |
		sed 's/\x1b\[[0-9;]*m//g')
	[ -n "$own" ] || fail "$name: device reported no address"
	# The announce carries LXMF app_data (display name, no stamp cost)
	# and the device's ratchet. From then on the peer encrypts to that
	# ratchet, so the echoes below decrypt with it, not the identity key.
	local ratchet
	ratchet=$(device_ratchet "$dev_log")
	[ -n "$ratchet" ] || fail "$name: device logged no ratchet, see $dev_log"
	grep -q "^LXMF DEVICE ANNOUNCE $own ret-lxmf stamp_cost=None ratchet=$ratchet$" "$peer_log" ||
		fail "$name: peer did not parse the device's LXMF announce and ratchet, see $peer_log"
	for n in $(seq 1 $COUNT_LXMF); do
		grep -q "^LXMF RECEIVED validated $own |hello #$n$" "$peer_log" ||
			fail "$name: peer did not validate hello #$n, see $peer_log"
		grep -q "LXMF DELIVERED #$n " "$dev_log" ||
			fail "$name: no delivery proof for #$n, see $dev_log"
		grep -q "LXMF RECEIVED verified from $LXMF_PEER: |echo: hello #$n" "$dev_log" ||
			fail "$name: device did not verify echo #$n, see $dev_log"
		grep -q "^REPLY DELIVERED echo: hello #$n$" "$peer_log" ||
			fail "$name: device did not prove echo #$n, see $peer_log"
		grep -q "^LXMF RECEIVED validated $own |re: echo: hello #$n$" "$peer_log" ||
			fail "$name: peer did not validate the device's reply to #$n, see $peer_log"
	done
	grep -q "DONE $COUNT_LXMF/$COUNT_LXMF delivered, $COUNT_LXMF/$COUNT_LXMF echoes" "$dev_log" ||
		fail "$name: want DONE $COUNT_LXMF/$COUNT_LXMF, see $dev_log"
	if [ "$mode" = direct ]; then
		# Echoes came over the peer's link to the device; a large message
		# as a Resource, one over RET_RESOURCE_MAX_SIZE refused.
		grep -q "inbound link .* active" "$dev_log" ||
			fail "lxmf-direct: no inbound link on the device, see $dev_log"
		grep -q "LXMF RECEIVED verified from $LXMF_PEER: |big .*(3000 bytes)" "$dev_log" ||
			fail "lxmf-direct: big message not delivered as a resource, see $dev_log"
		grep -q "^REPLY DELIVERED big$" "$peer_log" ||
			fail "lxmf-direct: big message not proved, see $peer_log"
		# -27 is -EFBIG: refused for its size, not anything else.
		grep -q "refusing delivery resource .*: -27" "$dev_log" ||
			fail "lxmf-direct: oversized message not refused for its size, see $dev_log"
		grep -q "^REPLY REJECTED huge$" "$peer_log" ||
			fail "lxmf-direct: sender did not see the refusal, see $peer_log"
		# The device's own DIRECT sends: its quotes of mid and big are
		# too long for one packet; mid fits a link packet, big (cut to
		# the sample's 1024) goes as a Resource. Intact on arrival.
		grep -q "DIRECT message .* sent as a packet" "$dev_log" ||
			fail "lxmf-direct: device sent no DIRECT packet, see $dev_log"
		grep -q "DIRECT message .* sent as a resource" "$dev_log" ||
			fail "lxmf-direct: device sent no DIRECT resource, see $dev_log"
		grep -q "resource proved: .* bytes delivered" "$dev_log" ||
			fail "lxmf-direct: device's resource not proved, see $dev_log"
		[ "$(grep -c "DIRECT message .*: delivered" "$dev_log")" -ge 2 ] ||
			fail "lxmf-direct: device's DIRECT messages not confirmed, see $dev_log"
		grep -q "^LXMF RECEIVED validated $own |re: mid (314 bytes)$" "$peer_log" ||
			fail "lxmf-direct: peer did not validate the device's DIRECT packet, see $peer_log"
		grep -q "^LXMF RECEIVED validated $own |re: big (1024 bytes)$" "$peer_log" ||
			fail "lxmf-direct: peer did not validate the device's DIRECT resource, see $peer_log"
		echo "   DIRECT: $COUNT_LXMF echoes, a 3000-byte resource delivered, 12000 bytes refused;"
		echo "   device sent DIRECT: 314 bytes as a packet, 1024 bytes as a resource"
	else
		echo "   $COUNT_LXMF/$COUNT_LXMF each way, signatures validated both ways (device $own)"
	fi
}

# ret_chat with its shell on a FIFO: chat_say types a line into it.
CHAT_PID=
chat_start() { # <log>
	local fifo="$LOGS/chat-in"
	rm -f "$fifo"
	mkfifo "$fifo"
	"$BUILD_CHAT/zephyr/zephyr.exe" --seed-random --flash="$FLASH" --uart_stdinout \
		<"$fifo" >"$1" 2>&1 &
	CHAT_PID=$!
	pids+=("$CHAT_PID")
	exec 7>"$fifo"
}

chat_stop() {
	exec 7>&-
	kill "$CHAT_PID" 2>/dev/null || true
	wait "$CHAT_PID" 2>/dev/null || true
}

chat_say() { printf '%s\n' "$1" >&7; }

# The device log without the shell's colour codes. Read through process
# substitution, not a pipe: grep -q (or awk's exit) stopping early would
# fail a pipe's writer under pipefail.
chat_log() { sed 's/\x1b\[[0-9;]*[A-Za-z]//g' "$1"; }

chat_has() { # <log> <pattern>
	grep -q -- "$2" <(chat_log "$1")
}

scenario_chat() {
	local dev_log="$LOGS/device-chat.log" dev2_log="$LOGS/device-chat-2.log"
	local peer_log="$LOGS/peer-chat.log" own long n

	"$PY" "$PEER_PROJECT/lxmf_peer.py" --config "$RNSD_CONFIG" --announce-interval 3 \
		>"$peer_log" 2>&1 &
	PEER_PID=$!
	pids+=("$PEER_PID")
	wait_for 30 "LXMF peer ready" grep -q "^PEER READY" "$peer_log"

	chat_start "$dev_log"
	wait_for 30 "the chat client" chat_has "$dev_log" "CHAT ADDRESS"
	own=$(awk '/CHAT ADDRESS/ {print $(NF-1); exit}' <(chat_log "$dev_log"))
	# The shell answers before the client is connected, and the peer
	# announces every 3 s: ask until it is listed.
	n=0
	until chat_has "$dev_log" "#[0-9] $LXMF_PEER ret-lxmf-peer"; do
		[ $n -lt 30 ] || fail "chat: the peer never showed in 'heard', see $dev_log"
		chat_say "heard"
		sleep 1
		n=$((n + 1))
	done

	# A name for it (left over from an earlier run on the same flash: replaced).
	chat_say "contact del peer"
	chat_say "contact add peer $LXMF_PEER"
	wait_for 10 "the contact" chat_has "$dev_log" "added peer"

	# By name, opportunistic; the peer echoes it into the inbox.
	chat_say "msg send peer hello chat"
	wait_for 10 "the send" chat_has "$dev_log" "queued #1 to peer (10 bytes)"
	wait_for 30 "delivery of #1" chat_has "$dev_log" "sent #1 to peer: delivered"
	wait_for 30 "the echo" chat_has "$dev_log" "new message #1 from peer: echo: hello chat"
	# LXMF proves a delivery before handling it: the peer's line can come
	# after the device's "delivered", but always before its echo.
	grep -q "^LXMF RECEIVED validated $own |hello chat$" "$peer_log" ||
		fail "chat: the peer did not validate the message, see $peer_log"
	chat_say "msg read 1"
	wait_for 10 "msg read" chat_has "$dev_log" "#1 from peer, sent 20[0-9-]* [0-9:]* UTC"

	# Too long for one packet: DIRECT, as a Resource; its echo comes back
	# DIRECT as well.
	long="hello long $(printf '%*s' 440 '' | tr ' ' '.')"
	chat_say "msg send peer $long"
	wait_for 10 "the long send" chat_has "$dev_log" "queued #2 to peer (451 bytes)"
	wait_for 60 "delivery of #2" chat_has "$dev_log" "sent #2 to peer: delivered"
	chat_has "$dev_log" "DIRECT message .* sent as a resource" ||
		fail "chat: the long message did not go as a resource, see $dev_log"
	wait_for 60 "the long echo" chat_has "$dev_log" "new message #2 from peer: echo: hello long"
	grep -q "^LXMF RECEIVED validated $own |hello long (451 bytes)$" "$peer_log" ||
		fail "chat: the peer did not validate the long message, see $peer_log"
	chat_say "msg inbox"
	wait_for 10 "the inbox" chat_has "$dev_log" "#2 peer, 457 bytes"
	chat_stop

	# The contact is in settings: there after a reboot, before the network.
	chat_start "$dev2_log"
	wait_for 30 "the contacts" chat_has "$dev2_log" "1 contact(s) loaded"
	chat_say "contact list"
	wait_for 10 "the contact after a reboot" chat_has "$dev2_log" "peer  *$LXMF_PEER"
	chat_stop
	stop_peer
	echo "   heard the peer, named it, messaged it by name (opportunistic and a"
	echo "   451-byte Resource), both echoes in the inbox; the contact survived a reboot"
}

LXMD_PID=
lxmd_n=0
start_lxmd() {
	lxmd_n=$((lxmd_n + 1))
	local log="$LOGS/lxmd-$lxmd_n.log"
	# Unbuffered: its log is how we know it is up.
	PYTHONUNBUFFERED=1 "$PEER_PROJECT/.venv/bin/lxmd" --config "$LXMD_DIR" \
		--rnsconfig "$RNSD_CONFIG" -p >"$log" 2>&1 &
	LXMD_PID=$!
	pids+=("$LXMD_PID")
	wait_for 30 "lxmd to start" grep -q "$NODE" "$log"
}

stop_pid() {
	kill "$1" 2>/dev/null || true
	wait "$1" 2>/dev/null || true
}

scenario_store_forward() {
	local send_log="$LOGS/sender-sf.log" go="$LOGS/sf-go"
	local dev1="$LOGS/device-sf-1.log" dev2="$LOGS/device-sf-2.log"
	local dev3="$LOGS/device-sf-3.log" n

	start_lxmd
	# --linger: it stays attached, so the device's path request for it
	# (after the unverified messages) is answered.
	"$PY" "$PEER_PROJECT/lxmf_send.py" --config "$RNSD_CONFIG" --node "$NODE" \
		--to-name ret-lxmf --count $COUNT_SF --size 600 --big 5000 --then 1 \
		--go-file "$go" --linger >"$send_log" 2>&1 &
	local send_pid=$!
	pids+=("$send_pid")
	wait_for 120 "sender ready (path to the node)" grep -q "^SENDER READY" "$send_log"
	local sender
	sender=$(awk '/^SENDER READY/ {print $3; exit}' "$send_log")

	# Boot 1: nothing waiting. The sender learns the device's key from
	# its announce.
	run_device "$BUILD_SF/zephyr/zephyr.exe" "$dev1"
	[ $RC -eq 0 ] || fail "store-forward: first sync failed (exit $RC), see $dev1"
	grep -q "SYNC DONE 0 0" "$dev1" || fail "store-forward: first sync not empty, see $dev1"
	local ratchet
	ratchet=$(device_ratchet "$dev1")
	[ -n "$ratchet" ] || fail "store-forward: device logged no ratchet, see $dev1"

	# Offline: deposit at the node.
	wait_for 30 "sender to see the device" grep -q "^TARGET" "$send_log"
	touch "$go"
	wait_for 120 "the deposits" grep -q "^DEPOSITED big$" "$send_log"
	for n in $(seq 1 $COUNT_SF); do
		grep -q "^DEPOSITED stored #$n$" "$send_log" ||
			fail "store-forward: stored #$n not deposited, see $send_log"
	done
	grep -q "^DEPOSITED big$" "$send_log" || fail "store-forward: big not deposited"
	# Encrypted to the ratchet the device announced: its sync must decrypt
	# with the ratchet.
	grep -q "^TARGET .* ratchet=$ratchet$" "$send_log" ||
		fail "store-forward: sender did not learn the device's ratchet, see $send_log"
	for n in $(seq 1 $COUNT_SF); do
		grep -q "^ENCRYPTED stored #$n ratchet=$ratchet$" "$send_log" ||
			fail "store-forward: stored #$n not encrypted to the ratchet, see $send_log"
	done
	local store="$LXMD_DIR/storage/lxmf/messagestore" held
	[ -d "$store" ] || fail "store-forward: no lxmd message store at $store"
	held=$(find "$store" -type f | wc -l)
	[ "$held" -eq $((COUNT_SF + 1)) ] ||
		fail "store-forward: node holds $held messages, want $((COUNT_SF + 1))"

	# Boot 2: the sync collects them, and keeps the sender's key.
	run_device "$BUILD_SF/zephyr/zephyr.exe" "$dev2"
	grep -q "keeping the key of LXMF sender ${sender:0:8}" "$dev2" ||
		fail "store-forward: the sender's key was not kept, see $dev2"

	# Boot 3: a fresh process knows the sender only from flash.
	touch "$go.2"
	wait_for 60 "the later deposit" grep -q "^DEPOSITED later #1$" "$send_log"
	run_device "$BUILD_SF/zephyr/zephyr.exe" "$dev3"
	stop_pid "$send_pid"
	stop_pid "$LXMD_PID"
	[ $RC -eq 0 ] || fail "store-forward: third sync failed (exit $RC), see $dev3"
	grep -q "LXMF RECEIVED verified from $sender: |later #1" "$dev3" ||
		fail "store-forward: later #1 not verified with the kept key, see $dev3"
	# And the key came from flash, not from a fresh announce this boot.
	! grep -q "path request for ${sender:0:8}" "$dev3" ||
		fail "store-forward: boot 3 had to ask for the sender's path, see $dev3"
	! grep -q "keeping the key of LXMF sender" "$dev3" ||
		fail "store-forward: boot 3 learned the key anew, see $dev3"

	grep -q "SYNC DONE 0 $COUNT_SF" "$dev2" ||
		fail "store-forward: second sync failed, see $dev2"
	for n in $(seq 1 $COUNT_SF); do
		grep -q "LXMF RECEIVED [A-Za-z]* from $sender: |stored #$n\b" "$dev2" ||
			fail "store-forward: stored #$n not delivered, see $dev2"
	done
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
	echo "   $COUNT_SF/$COUNT_SF collected (encrypted to the device's ratchet) and acknowledged,"
	echo "   oversized one left ($unverified unverified: sender unseen);"
	echo "   after a reboot the kept key verifies the sender"
}

# Runs after store-forward: the sender key it kept in the shared flash is what
# verifies "later #1" here.
scenario_sleep() {
	local send_log="$LOGS/sender-sleep.log" go="$LOGS/sleep-go" dev="$LOGS/device-sleep.log"

	# A fresh rnsd: store-forward just asked it for the node's path, and
	# rnsd drops repeat path requests for 45 s.
	fresh_rnsd
	start_lxmd
	"$PY" "$PEER_PROJECT/lxmf_send.py" --config "$RNSD_CONFIG" --node "$NODE" \
		--to-name ret-sleep --count 2 --prefix "night #" --then 1 --later-size 600 \
		--go-file "$go" --linger \
		>"$send_log" 2>&1 &
	local send_pid=$!
	pids+=("$send_pid")
	wait_for 120 "sender ready (path to the node)" grep -q "^SENDER READY" "$send_log"
	local sender
	sender=$(awk '/^SENDER READY/ {print $3; exit}' "$send_log")

	RC=0
	timeout 300 "$BUILD_SLEEP/zephyr/zephyr.exe" --seed-random --flash="$FLASH" >"$dev" 2>&1 &
	local dev_pid=$!
	pids+=("$dev_pid")
	# Deposit only while it sleeps: after wake 1, then after wake 2.
	wait_for 60 "the first sleep" grep -q "SLEEPING" "$dev"
	touch "$go"
	wait_for 60 "the night deposits" grep -q "^DEPOSITED night #2$" "$send_log"
	wait_for 60 "the second sleep" bash -c "[ \$(grep -c SLEEPING '$dev') -ge 2 ]"
	touch "$go.2"
	wait "$dev_pid" || RC=$?
	stop_pid "$send_pid"
	stop_pid "$LXMD_PID"

	[ $RC -eq 0 ] || fail "sleep: device exit $RC, see $dev"
	local syncs
	syncs=$(grep -o "SYNC DONE -\?[0-9]* [0-9]*" "$dev" | tr '\n' ' ')
	[ "$syncs" = "SYNC DONE 0 0 SYNC DONE 0 2 SYNC DONE 0 1 " ] ||
		fail "sleep: syncs were '$syncs', want 0, 2 and 1 messages, see $dev"
	grep -q "LXMF RECEIVED .* from $sender: |night #1" "$dev" || fail "sleep: night #1 missing"
	grep -q "LXMF RECEIVED .* from $sender: |night #2" "$dev" || fail "sleep: night #2 missing"
	grep -q "LXMF RECEIVED verified from $sender: |later #1" "$dev" ||
		fail "sleep: later #1 not verified, see $dev"
	# Built with a 20 s ratchet interval, under the 30 s sleep: every
	# wake rotates before it syncs. "later #1", deposited before wake 3
	# to the ratchet wake 2 announced, then decrypts with a ratchet that
	# is no longer the newest.
	local enc newest
	enc=$(awk '/^ENCRYPTED later #1 / {sub("ratchet=", "", $4); print $4; exit}' "$send_log")
	newest=$(device_ratchet "$dev")
	[ -n "$enc" ] && [ "$enc" != None ] ||
		fail "sleep: later #1 not encrypted to a ratchet, see $send_log"
	grep -q "ratchet $enc" "$dev" || fail "sleep: later #1's ratchet was never the device's"
	[ "$enc" != "$newest" ] || fail "sleep: no ratchet rotation before wake 3, see $dev"
	awk '/SLEEPING/ {s++} /new ratchet/ && s == 2 {ok = 1} END {exit !ok}' "$dev" ||
		fail "sleep: the ratchet did not rotate at wake 3, see $dev"
	# Its reply quotes 600 bytes: DIRECT, as a resource, proved before
	# the device suspended.
	local own
	own=$(awk '/^TARGET/ {print $2; exit}' "$send_log")
	grep -q "DIRECT message .* sent as a resource" "$dev" ||
		fail "sleep: the long reply did not go DIRECT, see $dev"
	grep -q "^RECEIVED validated $own re: later #1 (604 bytes)$" "$send_log" ||
		fail "sleep: the sender did not get the DIRECT reply, see $send_log"
	awk '/DIRECT message .*: delivered/ {d = 1} /-> SUSPENDED/ && d {ok = 1} END {exit !ok}' \
		"$dev" || fail "sleep: the DIRECT reply was not proved before suspending, see $dev"
	# No connection held between wakes; one announce per wake.
	local suspends announces
	suspends=$(grep -c -- "-> SUSPENDED" "$dev" || true)
	announces=$(grep -c "announced own destination" "$dev" || true)
	[ "$suspends" -eq 3 ] || fail "sleep: $suspends suspends, want 3"
	[ "$announces" -eq 3 ] || fail "sleep: $announces announces, want 3"
	grep -q "DONE 3/3 wakes synced" "$dev" || fail "sleep: want DONE 3/3, see $dev"
	echo "   3 wakes: mail deposited while asleep collected at the next wake;"
	echo "   a 604-byte reply delivered DIRECT before suspending;"
	echo "   the ratchet rotated at wake 3, the older one still decrypting"
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

tcp_open() { (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; }

air_node() { # <name> <udp port> <enable_transport>: a LoRa node's config dir
	local dir="$LOGS/air-$1"
	mkdir -p "$dir/interfaces"
	ln -sf "$LORA_CONFIG/interfaces/AirInterface.py" "$dir/interfaces/AirInterface.py"
	cat >"$dir/config" <<CONFIG
[reticulum]
  enable_transport = $3
  share_instance = No
  panic_on_interface_error = No

[logging]
  loglevel = 4

[interfaces]
  [[LoRa air]]
    type = AirInterface
    enabled = yes
    air_port = $AIR_PORT
    local_port = $2
CONFIG
}

# LoRa peers announce once, at start, unless told otherwise: the network
# then has to keep and serve the paths it learned.
start_lora_peer() { # <name> [peer args...]: sets LORA_PID
	local name=$1 log="$LOGS/air-$1.log"
	shift
	"$PY" "$PEER_PROJECT/peer.py" --config "$LOGS/air-$name" --identity "$LOGS/air-$name/identity" \
		--announce-interval 3600 "$@" >"$log" 2>&1 &
	LORA_PID=$!
	pids+=("$LORA_PID")
	wait_for 30 "LoRa peer $name" grep -q "^ANNOUNCED$" "$log"
}

start_hub_peer() { # <log> <identity> [peer args...]: a peer on the hub's shared instance
	local log=$1 id=$2
	shift 2
	"$PY" "$PEER_PROJECT/peer.py" --config "$LOGS/air-hub" --identity "$id" \
		--announce-interval 3600 "$@" >"$log" 2>&1 &
	pids+=("$!")
}

start_hub() { # <log>: sets HUB_PID
	PYTHONUNBUFFERED=1 "$RNSD" --config "$LOGS/air-hub" -vvv >"$1" 2>&1 &
	HUB_PID=$!
	pids+=("$HUB_PID")
	wait_for 30 "the hub" tcp_open $LORA_TCP_PORT
}

stop_pid_wait() { # <pid>
	kill "$1" 2>/dev/null || true
	wait "$1" 2>/dev/null || true
}

start_gateway() { # <build> <log>: sets GW_PID; the same flash every boot
	"$1/zephyr/zephyr.exe" --seed-random --flash="$LOGS/gw-flash.bin" >"$2" 2>&1 &
	GW_PID=$!
	pids+=("$GW_PID")
}

all_proved() { # <scenario> <sender log> <count> <receiver log>
	local n
	wait_for 90 "delivery ($2)" grep -q "^SEND \(PROVED\|FAILED\) $3$" "$2"
	for n in $(seq 1 "$3"); do
		grep -q "^SEND PROVED $n$" "$2" || fail "$1: message $n not proved, see $2"
		grep -q "^RECEIVED sent #$n$" "$4" || fail "$1: #$n not received, see $4"
	done
}

# Who hears whom:
#
#   hub == gateway ~~ n1
#                  ~~ n3          n1 and n3 cannot hear each other
#                  ~~ repeater ~~ n2     n2 cannot hear the gateway
scenario_lora_gateway() {
	local hub_log="$LOGS/rnsd-lora.log" air_log="$LOGS/air.log" gw_log="$LOGS/gateway.log"
	local dev_log="$LOGS/device-lora.log" hub_dir="$LOGS/air-hub" id n3_pid p
	local first=${#pids[@]}

	tcp_open $LORA_TCP_PORT && fail "port $LORA_TCP_PORT already in use"
	rm -f "$LOGS/gw-flash.bin"
	# A copy: the paths one run learns must not carry over.
	cp -r "$LORA_CONFIG"/. "$hub_dir"
	air_node n1 $AIR_N1 No
	air_node n2 $AIR_N2 No
	air_node n3 $AIR_N3 No
	air_node repeater $AIR_REPEATER Yes

	"$PY" "$PEER_PROJECT/air.py" --port $AIR_PORT --node gw=$AIR_GW --node n1=$AIR_N1 \
		--node n2=$AIR_N2 --node n3=$AIR_N3 --node repeater=$AIR_REPEATER \
		--link gw-n1 --link gw-n3 --link gw-repeater --link repeater-n2 >"$air_log" 2>&1 &
	pids+=("$!")
	wait_for 10 "air" grep -q "^AIR READY" "$air_log"

	start_hub "$hub_log"
	start_gateway "$BUILD_GW" "$gw_log"
	wait_for 30 "the gateway's uplink" grep -q "uplink connected" "$gw_log"
	id=$(grep -o "transport node <[0-9a-f]*>" "$gw_log") || fail "lora-gateway: no identity, see $gw_log"
	grep -q "7031 bps" "$gw_log" || fail "lora-gateway: wrong LoRa bitrate, see $gw_log"

	# n1 announces every 15 s: the device links to what it hears announce.
	start_lora_peer n1 --reply --announce-interval 15

	# A device on the hub <-> n1 through the gateway: DATA, proofs, replies,
	# a link with a resource (split frames both ways).
	run_device "$BUILD_GW_DEV/zephyr/zephyr.exe" "$dev_log"
	[ $RC -eq 0 ] || fail "lora-gateway: device exit $RC, want 0, see $dev_log and $gw_log"
	check_messages lora-gateway "$dev_log" "$LOGS/air-n1.log" $COUNT_NAME proof
	grep -Eq "air rx (25[5-9]|2[6-9][0-9]|[34][0-9]{2}|50[0-8]) bytes" "$gw_log" ||
		fail "lora-gateway: no split packet reassembled, see $gw_log"
	echo "   device on the hub <-> n1 over LoRa: $COUNT_NAME/$COUNT_NAME proved, replies, link, resource"

	# Two LoRa hops: the hub reaches n2 through the repeater.
	PYTHONUNBUFFERED=1 "$RNSD" --config "$LOGS/air-repeater" -vv >"$LOGS/air-repeater.log" 2>&1 &
	pids+=("$!")
	start_lora_peer n2
	start_hub_peer "$LOGS/hub-peer.log" "$hub_dir/identity" --send-to "$LORA_N2"
	all_proved lora-gateway "$LOGS/hub-peer.log" 3 "$LOGS/air-n2.log"
	grep -Eq "^SEND PATH ([3-9]|[1-9][0-9]) hops" "$LOGS/hub-peer.log" ||
		fail "lora-gateway: n2 is not behind the gateway and the repeater, see $LOGS/hub-peer.log"
	echo "   two LoRa hops: 3/3 proved ($(grep -o 'SEND PATH .*' "$LOGS/hub-peer.log"))"

	# LoRa to LoRa through the gateway alone: the hub is down.
	stop_pid_wait "$HUB_PID"
	wait_for 10 "the gateway to notice" grep -q "uplink down" "$gw_log"
	start_lora_peer n3 --send-to "$LORA_N1"
	n3_pid=$LORA_PID
	all_proved lora-gateway "$LOGS/air-n3.log" 3 "$LOGS/air-n1.log"
	echo "   hidden nodes, hub down: n3 -> n1 3/3 proved through the gateway"

	# While the gateway is off, the hub comes back and X announces: X is a
	# destination the gateway has never heard of.
	stop_pid_wait "$GW_PID"
	start_hub "$hub_log.2"
	start_hub_peer "$LOGS/hub-x.log" "$hub_dir/x-identity"
	wait_for 30 "hub peer X" grep -q "^ANNOUNCED$" "$LOGS/hub-x.log"
	# Past the hub's one retry of X's announce (PATHFINDER_G 5 s): the
	# gateway must not hear it when it connects.
	sleep 7

	# The gateway reboots: the same identity, its paths from flash. On
	# reconnecting, its tunnel brings back the paths the hub learned through
	# it (n2 announced only once).
	start_gateway "$BUILD_GW" "$gw_log.2"
	wait_for 30 "the gateway to restart" grep -q "uplink connected" "$gw_log.2"
	grep -q "$id" "$gw_log.2" || fail "lora-gateway: identity changed across a reboot, see $gw_log.2"
	grep -Eq "transport: [1-9][0-9]* paths loaded" "$gw_log.2" ||
		fail "lora-gateway: no paths came back from flash, see $gw_log.2"
	wait_for 15 "the tunnel" grep -q "Tunnel endpoint .* reappeared" "$hub_log.2"
	grep -q "Restored path to <$LORA_N2>" "$hub_log.2" ||
		fail "lora-gateway: the tunnel did not restore the path to n2, see $hub_log.2"
	# Padded past one LoRa frame: the gateway splits it.
	start_hub_peer "$LOGS/hub-peer-2.log" "$hub_dir/identity2" --send-to "$LORA_N2" --send-count 1 \
		--send-size 350
	wait_for 90 "delivery after the restarts" grep -q "^SEND \(PROVED\|FAILED\) 1$" \
		"$LOGS/hub-peer-2.log"
	grep -q "^SEND PROVED 1$" "$LOGS/hub-peer-2.log" ||
		fail "lora-gateway: not delivered after the restarts, see $LOGS/hub-peer-2.log"
	grep -Eq "air tx (25[5-9]|2[6-9][0-9]|[34][0-9]{2}|50[0-8]) bytes" "$gw_log.2" ||
		fail "lora-gateway: no split packet sent, see $gw_log.2"
	echo "   gateway reboot: same identity, paths from flash; tunnel restored the path to n2"

	# n3 never heard X: its path request goes up through the gateway.
	stop_pid_wait "$n3_pid"
	start_lora_peer n3 --send-to "$LORA_X"
	n3_pid=$LORA_PID
	all_proved lora-gateway "$LOGS/air-n3.log" 3 "$LOGS/hub-x.log"
	# Found by asking: the gateway forwarded the request, the hub answered it.
	grep -q "Answering path request for <$LORA_X> on TCPInterface\[Client on ret-client TCP/" \
		"$hub_log.2" || fail "lora-gateway: no path request for X reached the hub, see $hub_log.2"
	echo "   path discovery: n3 found X behind the hub, 3/3 proved"

	# IFAC on the uplink: a wrong passphrase is ignored, the right one works.
	stop_pid_wait "$GW_PID"
	start_gateway "$BUILD_GW_IFAC_BAD" "$gw_log.bad"
	wait_for 30 "the wrong-passphrase gateway" grep -q "uplink connected" "$gw_log.bad"
	wait_for 15 "the hub to ignore it" grep -q "IFAC violation" "$hub_log.2"
	stop_pid_wait "$GW_PID"
	start_gateway "$BUILD_GW_IFAC" "$gw_log.ifac"
	wait_for 30 "the IFAC gateway" grep -q "uplink connected" "$gw_log.ifac"
	# The hub's path to n1 through the gateway's previous connection is dead:
	# send once n1's announce has come in over this one.
	wait_for 40 "the hub to route n1 over IFAC" grep -q \
		"Destination <$LORA_N1> is now .* on TCPInterface\[Client on ret-client TCP IFAC" "$hub_log.2"
	start_hub_peer "$LOGS/hub-peer-3.log" "$hub_dir/identity3" --send-to "$LORA_N1" --send-count 1
	wait_for 90 "delivery over IFAC" grep -q "^SEND \(PROVED\|FAILED\) 1$" "$LOGS/hub-peer-3.log"
	grep -q "^SEND PROVED 1$" "$LOGS/hub-peer-3.log" ||
		fail "lora-gateway: not delivered over the IFAC uplink, see $LOGS/hub-peer-3.log"
	echo "   IFAC uplink: wrong passphrase ignored, right one delivers"

	# Leave nothing running for the scenarios after this one.
	for p in "${pids[@]:first}"; do
		stop_pid_wait "$p"
	done
}

for s in "${scenarios[@]}"; do
	echo "== scenario $s"
	case $s in
	plain | ratchets | no-prove) scenario_announced "$s" ;;
	ifac) scenario_ifac ;;
	lora-gateway) scenario_lora_gateway ;;
	echo) scenario_echo ;;
	lxmf) scenario_lxmf ;;
	lxmf-direct) scenario_lxmf direct ;;
	chat) scenario_chat ;;
	store-forward) scenario_store_forward ;;
	sleep) scenario_sleep ;;
	late) scenario_late ;;
	stall) scenario_stall ;;
	bootdown) scenario_bootdown ;;
	restart) scenario_restart ;;
	*) fail "unknown scenario $s" ;;
	esac
done

echo "PASS: ${scenarios[*]}"
