#!/usr/bin/env bash
set -euo pipefail
binary=$(realpath "${1:?Usage: test-guard.sh <compiled service test binary>}")
if [[ ${2:-} != --inside ]]; then
    for tool in ip nft unshare timeout; do
        command -v "$tool" >/dev/null || { echo "Guard smoke requires $tool" >&2; exit 1; }
    done
    export GUARD_HOST_NETNS
    GUARD_HOST_NETNS=$(readlink /proc/self/ns/net)
    if unshare --user --map-root-user --net true 2>/dev/null; then
        exec timeout -k 5s 60s unshare --user --map-root-user --net --fork --kill-child bash "$0" "$binary" --inside
    else
        exec sudo -n timeout -k 5s 60s env GUARD_HOST_NETNS="$GUARD_HOST_NETNS" \
            unshare --net --fork --kill-child bash "$0" "$binary" --inside
    fi
fi
[[ $(readlink /proc/self/ns/net) != "$GUARD_HOST_NETNS" ]] || { echo 'Refusing host firewall changes' >&2; exit 1; }
export GUARD_SMOKE_DIR
GUARD_SMOKE_DIR=$(mktemp -d /tmp/tuncli-guard-test.XXXXXXXX)
fixture_pid= client_pid=
cleanup() {
    status=$?
    trap - EXIT
    [[ -z $client_pid ]] || kill "$client_pid" 2>/dev/null || true
    [[ -z $fixture_pid ]] || kill "$fixture_pid" 2>/dev/null || true
    [[ -z $client_pid ]] || wait "$client_pid" 2>/dev/null || true
    [[ -z $fixture_pid ]] || wait "$fixture_pid" 2>/dev/null || true
    cat "$GUARD_SMOKE_DIR"/*.log 2>/dev/null || true
    rm -rf -- "$GUARD_SMOKE_DIR"
    exit "$status"
}
trap cleanup EXIT
ip link set lo up
ip link add guard-wan type veth peer name guard-client
ip address add 192.0.2.2/24 dev guard-wan
ip -6 address add fd00:2026::2/64 dev guard-wan nodad
ip link set guard-wan up
ip address add 1.1.1.1/32 dev lo
"$binary" -test.v -test.timeout=55s -test.run '^TestGuardFixture$' >"$GUARD_SMOKE_DIR/fixture.log" 2>&1 &
fixture_pid=$!
unshare --net bash -euo pipefail -c '
    for ((i=0;i<200;i++)); do
        [[ -e "$GUARD_SMOKE_DIR/ready" ]] && break
        sleep 0.025
    done
    [[ -e "$GUARD_SMOKE_DIR/ready" ]]
    ip link set lo up
    ip address add 192.0.2.1/24 dev guard-client
    ip -6 address add fd00:2026::1/64 dev guard-client nodad
    ip link set guard-client up
    ip route add default via 192.0.2.2
    ip -6 route add default via fd00:2026::2
    exec "$1" -test.v -test.timeout=45s -test.run "^TestGuardSmoke$"
' bash "$binary" >"$GUARD_SMOKE_DIR/client.log" 2>&1 &
client_pid=$!
for ((i=0;i<200;i++)); do
    [[ $(readlink "/proc/$client_pid/ns/net") != $(readlink /proc/self/ns/net) ]] && break
    sleep 0.025
done
ip link set guard-client netns "$client_pid"
for ((i=0;i<200;i++)); do
    [[ -e "$GUARD_SMOKE_DIR/fixture-ready" ]] && break
    kill -0 "$fixture_pid" 2>/dev/null
    sleep 0.025
done
[[ -e "$GUARD_SMOKE_DIR/fixture-ready" ]]
touch "$GUARD_SMOKE_DIR/ready"
wait "$client_pid"
client_pid=
wait "$fixture_pid"
fixture_pid=
