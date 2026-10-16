#!/usr/bin/env bash
set -euo pipefail

binary=$(realpath "${1:?Usage: test-tun.sh <compiled runner test binary>}")
if [[ ${2:-} != --inside ]]; then
    for tool in ip unshare timeout; do
        command -v "$tool" >/dev/null || { echo "TUN smoke requires $tool" >&2; exit 1; }
    done
    [[ -c /dev/net/tun ]] || { echo 'TUN smoke requires /dev/net/tun' >&2; exit 1; }
    export TUN_SMOKE_HOST_NETNS
    TUN_SMOKE_HOST_NETNS=$(readlink /proc/self/ns/net)
    # Probe separately: a test failure must never trigger a second privileged run.
    if [[ $(id -u) == 0 ]]; then
        exec timeout -k 5s 100s unshare --net --fork --kill-child bash "$0" "$binary" --inside
    elif unshare --user --map-root-user --net true 2>/dev/null; then
        exec timeout -k 5s 100s unshare --user --map-root-user --net --fork --kill-child bash "$0" "$binary" --inside
    else
        echo 'User namespaces unavailable; using passwordless sudo for isolated network namespaces.' >&2
        exec sudo -n env TUN_SMOKE_HOST_NETNS="$TUN_SMOKE_HOST_NETNS" timeout -k 5s 100s \
            unshare --net --fork --kill-child bash "$0" "$binary" --inside
    fi
fi

[[ $(readlink /proc/self/ns/net) != "$TUN_SMOKE_HOST_NETNS" ]] || { echo 'Refusing to change host networking' >&2; exit 1; }
export TUN_SMOKE_DIR
TUN_SMOKE_DIR=$(mktemp -d /tmp/tuncli-net-test.XXXXXXXX)
fixture_pid= client_pid=
cleanup() {
    status=$?
    trap - EXIT
    [[ -z $client_pid ]] || kill "$client_pid" 2>/dev/null || true
    [[ -z $fixture_pid ]] || kill "$fixture_pid" 2>/dev/null || true
    [[ -z $client_pid ]] || wait "$client_pid" 2>/dev/null || true
    [[ -z $fixture_pid ]] || wait "$fixture_pid" 2>/dev/null || true
    cat "$TUN_SMOKE_DIR"/*.log 2>/dev/null || true
    rm -rf -- "$TUN_SMOKE_DIR"
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

ip link set lo up
ip link add smoke-wan type veth peer name smoke-client
ip address add 192.0.2.2/24 dev smoke-wan
ip -6 address add fd00:2026::2/64 dev smoke-wan nodad
ip link set smoke-wan up
ip route add default dev smoke-wan
ip -6 route add default dev smoke-wan
ip address add 203.0.113.10/32 dev lo
ip -6 address add 2001:db8::10/128 dev lo nodad
"$binary" -test.v -test.timeout=85s -test.run '^TestTUNSmokeFixture$' >"$TUN_SMOKE_DIR/fixture.log" 2>&1 &
fixture_pid=$!

unshare --net bash -euo pipefail -c '
    for ((i=0;i<200;i++)); do
        [[ -e "$TUN_SMOKE_DIR/network-ready" ]] && break
        sleep 0.025
    done
    [[ -e "$TUN_SMOKE_DIR/network-ready" ]]
    ip link set lo up
    ip address add 192.0.2.1/24 dev smoke-client
    ip -6 address add fd00:2026::1/64 dev smoke-client nodad
    ip link set smoke-client up
    ip route add default via 192.0.2.2
    ip -6 route add default via fd00:2026::2
    exec "$1" -test.v -test.timeout=80s -test.run "^TestTUNSmoke$"
' bash "$binary" >"$TUN_SMOKE_DIR/client.log" 2>&1 &
client_pid=$!
# Wait until unshare has created the client namespace before moving the veth.
for ((i=0;i<200;i++)); do
    if [[ $(readlink "/proc/$client_pid/ns/net") != $(readlink /proc/self/ns/net) ]]; then break; fi
    sleep 0.025
done
ip link set smoke-client netns "$client_pid"
for ((i=0;i<200;i++)); do
    [[ -e "$TUN_SMOKE_DIR/fixture-ready" ]] && break
    kill -0 "$fixture_pid" 2>/dev/null || { echo 'Fixture failed to start' >&2; exit 1; }
    sleep 0.025
done
[[ -e "$TUN_SMOKE_DIR/fixture-ready" ]]
touch "$TUN_SMOKE_DIR/network-ready"
wait "$client_pid"
client_pid=
# Let the fixture exit normally so its cleanup and test status are checked too.
touch "$TUN_SMOKE_DIR/done"
wait "$fixture_pid"
fixture_pid=
