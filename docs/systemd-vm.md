# systemd VM acceptance checks

Use a disposable Linux VM with systemd as PID 1, nftables, TUN, iproute2, a working
VPN node and two ordinary user accounts. Do not run the lifecycle checks on a
shared host. Build with `make check-all && make build` first.

1. As the installation owner, use `tuncli add`, `tuncli routing` as needed and
   `tuncli select`. Save checksums of the original configuration and subscription
   files. Run `sudo tuncli service install`; this is the only privileged step for
   ordinary operation. Verify the checksums are unchanged, including legacy
   configuration after migration. All files under `/var/lib/tuncli` must be root
   owned; directories must be 0700 and secret files 0600.
2. Without sudo, exercise `status --json`, `logs`, `logs -f`, `select`, subscriptions,
   routing changes, `start --node/--mode`, `restart`, and `stop`. A stopped VPN must
   stay stopped while settings change; `restart` must report an error. Verify
   HTTP and SOCKS5 at `127.0.0.1:2080` in both modes, including after restart;
   the listener must close on stop. In proxy mode, normal system traffic is unblocked.
3. From the other user, run status/start/stop and attempt to read the Unix socket
   directly: all requests must return permission denied. Root must retain access.
   Check that raw engine options, executable paths and unknown operation names
   are rejected. Stop the daemon with systemctl: owner commands must return an
   unavailable error and no second VPN process may appear.
4. Start TUN, reboot without logging into the owner account, and inspect from the
   VM console as root: desired=true, a working VPN and active protection must be
   present. Check `systemd-analyze critical-chain network-pre.target` and the
   journal to confirm the guard precedes network configuration. Repeat after
   `tuncli stop`: desired=false, no TUN, no guard table, normal internet.
5. While connected, kill the daemon and then Xray (for an XHTTP node). Inspect
   nftables and packet captures: there must be no unmarked IPv4/IPv6 or DNS leak.
   systemd must reap all old children and restart the daemon. Direct access must
   remain closed until a probe succeeds. Repeat a systemctl restart, suspend/
   resume, switch network, and make the selected server unreachable. Two failed
   probes must close direct access within 30 seconds; retries use the same node.
6. Submit a valid selection whose connection cannot start, then invalid routing
   and an update that removes the selected node. The previous settings and
   subscription must remain usable; verify rollback in the status/journal. An
   update affecting only an unselected node must preserve the active connection.
7. During a settings update, kill the daemon, restart it and check that the
   transaction journal restores the previous settings. Deny nft access: protected
   TUN must refuse to start. Restore nft, run `sudo tuncli service recover`, and
   check desired=false, stopped daemon, and normal internet.
8. Create a foreign nftables table. Uninstall with `sudo tuncli service uninstall`:
   tuncli units and its table must be gone, the foreign table must survive and
   `/var/lib/tuncli` must remain as a root-only settings export.

Record the VM image, kernel, systemd/nft versions and results. Namespace tests
cover the firewall policy and existing TUN routing independently; they do not
substitute for these boot, suspend, real-server and systemd checks.
