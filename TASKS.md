# Tasks

- [ ] First live run against 203.0.113.10 with real VPN + GitHub credentials (portal login status codes, OpenVPN port/proto, P4 VPN→WAN SNAT)
- [ ] Find the portal hostname on the `*.example.com` cert and make it the `--portal-host` default
- [ ] SPEC §4: Linux netns/veth isolation (`ghvpn-net`) for the EC2 daemon
- [ ] SPEC §8.1: SOCKS5 + HTTP CONNECT proxy with GitHub allowlist (`ghvpn-proxy`)
- [ ] SPEC §9: `ghvpnd` daemon + control socket + `ghvpn` CLI, reusing `ghvpn-mgmt`
- [ ] SPEC §7.2: AWS Secrets Manager loading, `secrecy`/zeroize for in-memory secrets
- [ ] SPEC §14.2: docker-compose OpenVPN test server with `auth-user-pass-verify` + TOTP
