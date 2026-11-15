#!/usr/bin/env bash
# PUT/GET with a native seedkernel on every end: two holders and an initiator, fresh for
# every run (docs/PERFORMANCE.md, "QUIC and TCP on one pair"). The initiator is driven over
# its control socket by ctl/, built once with `go build` in that folder.
#
#   SEEDKERNEL=../../seedkernel/native/seedkernel.exe bash scripts/bench-native/run.sh
#
#   ARMS    lo-tcp lo-quic (default), wan-tcp, wan-quic
#   ROUNDS  how many times to run every arm, alternating (default 3)
#   SIZE    MiB per PUT (default 50), GETS per PUT (default 2)
#   WAN_TCP, WAN_QUIC  the remote holder for the wan arms, <key>.<contact>@tcp://host:port
#           and <key>.<contact>@quic://ip:port. Its local config must list the initiator's
#           key, printed below, in its group.
#   WORK    where keys, stores and logs go (default ~/seedbench-native). Not a temp folder:
#           Windows scans a binary's files there, which slows the first GET.
here=$(cd "$(dirname "$0")" && pwd)
wasm=$(cd "$here/../.." && pwd)
X=$(realpath "${SEEDKERNEL:?the native seedkernel binary}")
CTL=$(ls "$here"/ctl/ctl "$here"/ctl/ctl.exe 2>/dev/null | head -1)
[ -n "$CTL" ] || { echo "no driver: run 'go build' in $here/ctl"; exit 1; }
mkdir -p "${WORK:=$HOME/seedbench-native}" && cd "$WORK" || exit 1
base=(--policy "$wasm/bundle-policy.json" --bundle "$wasm/bundle/seedstore.skb" --guest-timeout 60000 --guest-memory 256)

# A node's key, which it prints on any run; its store starts empty every time.
key() {
  rm -rf "./$1" "./$1.control" "./$1.freshness.json"
  "$X" "${base[@]}" --dir "./$1" --key "./$1.key" --op files < /dev/null 2>&1 | sed -n '1s/.* //p'
}
pids=()
node() {
  local n=$1; shift
  rm -rf "./$n" "./$n.control" "./$n.freshness.json"
  "$X" "${base[@]}" --dir "./$n" --key "./$n.key" "$@" > "$n.log" 2>&1 &
  pids+=($!)
}
ready() {
  for _ in $(seq 60); do
    grep -q "^serving" "$1.log" && return 0
    sleep 0.5
  done
  echo "  $1 not ready"; tail -5 "$1.log"; return 1
}
stop() {
  kill "${pids[@]}" 2>/dev/null
  wait 2>/dev/null
  pids=()
}
trap stop EXIT
# A holder on loopback TCP and on QUIC, which binds every address.
holder() {
  node "$1" --local-config holder.json --listen "127.0.0.1:$2,quic=udp://0.0.0.0:$(($2 + 2))"
  ready "$1"
}
# What a dialer names a serving node by: <key>.<contact>, both off its log.
peer() { echo "$(sed -n '1s/.* //p' "$1.log").$(sed -n 's/^  contact //p' "$1.log")"; }

I=$(key i)
echo "initiator $I"
echo "{\"quota\": 4294967296, \"groups\": {\"cohort\": [\"$I\"]}}" > holder.json
echo '{"connsPerPeer": 8, "requestTimeoutMs": 30000}' > conns-tcp.json
echo '{"connsPerPeer": 4, "requestTimeoutMs": 30000}' > conns-quic.json

arm() {
  echo "== $1"
  local h1 h2 peers
  holder h1 47220 || return
  h1=$(peer h1)
  case $1 in
    lo-*) holder h2 47230 || return; h2=$(peer h2) ;;
    wan-tcp) h2=${WAN_TCP:?} ;;
    wan-quic) h2=${WAN_QUIC:?} ;;
  esac
  case $1 in
    lo-tcp) peers="$h1@tcp://127.0.0.1:47220,$h2@tcp://127.0.0.1:47230" ;;
    lo-quic) peers="$h1@quic://127.0.0.1:47222,$h2@quic://127.0.0.1:47232" ;;
    wan-tcp) peers="$h2,$h1@tcp://127.0.0.1:47220" ;;
    wan-quic) peers="$h2,$h1@quic://127.0.0.1:47222" ;;
  esac
  echo "{\"k\":1,\"m\":1,\"blockSize\":262144,\"maxMessageBytes\":524288,\"fanoutWindow\":64,\"windowTargetBytes\":25165824,\"groups\":{\"cohort\":[\"$I\",\"${h1%%.*}\",\"${h2%%.*}\"]}}" > initiator.json
  node i --local-config initiator.json --transport-config "conns-${1#*-}.json" --listen 127.0.0.1:47260 --peers "$peers"
  ready i && timeout 240 "$CTL" ./i "${SIZE:-50}" "${GETS:-2}" 2>&1 | sed 's/^/  /'
}
for _ in $(seq "${ROUNDS:-3}"); do
  for a in ${ARMS:-lo-tcp lo-quic}; do
    arm "$a"
    stop
  done
done
