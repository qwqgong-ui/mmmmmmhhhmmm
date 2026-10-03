#!/usr/bin/python
"""Own only the mihomo_tproxy nft table and recorded policy-route entries."""
import argparse
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import tomllib

import yaml

TABLE = 'mihomo_tproxy'
STATE_DIR = Path('/run/mihomo-tproxy')
STATE = STATE_DIR / 'state.json'


def run(*args, check=True, input=None):
    return subprocess.run(args, input=input, text=True, capture_output=True, check=check)


def cidrs(path, version):
    result = []
    for line in Path(path).read_text().splitlines():
        line = line.split('#', 1)[0].strip()
        if not line:
            continue
        network = ipaddress.ip_network(line, strict=False)
        if network.version != version:
            raise ValueError(f'{path}: wrong address family: {line}')
        result.append(str(network))
    return result


def parameters(settings):
    opts = tomllib.loads(Path(settings).read_text())
    core = yaml.safe_load(Path(opts['core_config']).read_text())
    tun = core.get('tun', {})
    if not all(tun.get(k) is True for k in ('enable', 'auto-route', 'auto-detect-interface')):
        raise ValueError('TUN fallback requires enable, auto-route and auto-detect-interface')
    if tun.get('auto-redirect', False):
        raise ValueError('Disable tun.auto-redirect before registering TPROXY')
    p = {k: opts[k] for k in ('proxy_mark', 'route_table', 'bypass_priority', 'proxy_priority')}
    p.update(port=core.get('tproxy-port', 0), bypass_mark=core.get('routing-mark', 0))
    limits = {'port': 65535, 'bypass_priority': 32765, 'proxy_priority': 32765,
              'proxy_mark': 0xffffffff, 'bypass_mark': 0xffffffff, 'route_table': 0xfffffffb}
    for k, maximum in limits.items():
        if type(p[k]) is not int or not 0 < p[k] <= maximum:
            raise ValueError(f'Invalid {k}')
    if p['route_table'] in (253, 254, 255):
        raise ValueError('A dedicated routing table is required')
    if p['proxy_mark'] == p['bypass_mark'] or p['bypass_priority'] >= p['proxy_priority']:
        raise ValueError('Marks must differ and bypass_priority must precede proxy_priority')
    dns = core.get('dns', {})
    p['fake4'] = str(ipaddress.IPv4Network(dns.get('fake-ip-range', '198.18.0.0/16'), strict=False))
    p['fake6'] = str(ipaddress.IPv6Network(dns.get('fake-ip-range6', '2001:2::/48'), strict=False))
    p['direct4'] = cidrs(opts['direct4'], 4)
    p['direct6'] = cidrs(opts['direct6'], 6)
    p['resolved'] = Path('/sys/fs/cgroup/system.slice/systemd-resolved.service').is_dir()
    return p


def nft_set(name, version, networks):
    elements = f"elements = {{ {', '.join(networks)} }};" if networks else ''
    return f'set {name} {{ type ipv{version}_addr; flags interval; auto-merge; {elements} }}'


def render(p):
    bypass, proxy = p['bypass_mark'], p['proxy_mark']
    resolved = (f'socket cgroupv2 level 2 "system.slice/systemd-resolved.service" '
                f'counter meta mark set {bypass} return' if p['resolved'] else '')
    private4 = ['0.0.0.0/8', '10.0.0.0/8', '127.0.0.0/8', '169.254.0.0/16',
                '172.16.0.0/12', '192.168.0.0/16', '224.0.0.0/4', '240.0.0.0/4']
    private6 = ['::/128', '::1/128', 'fc00::/7', 'fe80::/10', 'ff00::/8']
    return f'''table inet {TABLE} {{
{nft_set('direct4', 4, private4 + p['direct4'])}
{nft_set('direct6', 6, private6 + p['direct6'])}
chain output {{
    type route hook output priority mangle; policy accept;
    meta mark {bypass} counter return
    socket cgroupv2 level 2 "system.slice/mihomo.service" counter meta mark set {bypass} return
    {resolved}
    meta l4proto != {{ tcp, udp }} return
    th dport 53 counter meta mark set {proxy} return
    ip daddr {p['fake4']} counter meta mark set {proxy} return
    ip6 daddr {p['fake6']} counter meta mark set {proxy} return
    fib daddr type local counter meta mark set {bypass} return
    ip daddr @direct4 counter meta mark set {bypass} return
    ip6 daddr @direct6 counter meta mark set {bypass} return
    counter meta mark set {proxy}
}}
chain prerouting {{
    type filter hook prerouting priority mangle; policy accept;
    iifname "lo" meta mark {proxy} meta l4proto {{ tcp, udp }} socket transparent 1 counter accept
    iifname "lo" meta mark {proxy} meta l4proto {{ tcp, udp }} counter tproxy to :{p['port']} accept
}}
chain input {{
    type filter hook input priority filter; policy accept;
    iifname != "lo" meta l4proto {{ tcp, udp }} th dport {p['port']} counter drop
}}
}}
'''


def stop():
    if not STATE.exists():
        return
    p = json.loads(STATE.read_text())
    if run('nft', 'list', 'table', 'inet', TABLE, check=False).returncode == 0:
        run('nft', 'delete', 'table', 'inet', TABLE)
    for family in ('-4', '-6'):
        for priority, mark, table in ((p['proxy_priority'], p['proxy_mark'], p['route_table']),
                                     (p['bypass_priority'], p['bypass_mark'], 'main')):
            run('ip', family, 'rule', 'del', 'priority', str(priority), 'fwmark',
                f'{mark}/0xffffffff', 'lookup', str(table), check=False)
        run('ip', family, 'route', 'del', 'local', 'default', 'dev', 'lo',
            'table', str(p['route_table']), check=False)
    STATE.unlink()


def start(p):
    if Path('/etc/systemd/system/mihomo.service.d/30-transparent.conf').exists():
        raise ValueError('Previous manual TPROXY integration is still installed')
    if STATE.exists():
        stop()
    if run('nft', 'list', 'table', 'inet', TABLE, check=False).returncode == 0:
        raise ValueError(f'Unowned nft table {TABLE} already exists')
    for family in ('-4', '-6'):
        rules = json.loads(run('ip', family, '-j', 'rule', 'show').stdout)
        if any(r.get('priority') in (p['bypass_priority'], p['proxy_priority']) for r in rules):
            raise ValueError('Policy-rule priority already occupied')
        existing = run('ip', family, '-j', 'route', 'show', 'table', str(p['route_table']), check=False)
        if existing.stdout.strip() not in ('', '[]'):
            raise ValueError('Routing table already occupied')
    for _ in range(100):
        if all(run('ss', '-H', flag, f'sport = :{p["port"]}').stdout.strip()
               for flag in ('-lnt', '-lnu')):
            break
        time.sleep(0.1)
    else:
        raise ValueError('TPROXY TCP/UDP listeners did not become ready')
    ruleset = render(p)
    run('nft', '--check', '--file', '-', input=ruleset)
    STATE.write_text(json.dumps(p))
    try:
        for family in ('-4', '-6'):
            run('ip', family, 'route', 'add', 'local', 'default', 'dev', 'lo', 'table', str(p['route_table']))
            run('ip', family, 'rule', 'add', 'priority', str(p['bypass_priority']), 'fwmark',
                f'{p["bypass_mark"]}/0xffffffff', 'lookup', 'main')
            run('ip', family, 'rule', 'add', 'priority', str(p['proxy_priority']), 'fwmark',
                f'{p["proxy_mark"]}/0xffffffff', 'lookup', str(p['route_table']))
        run('nft', '--file', '-', input=ruleset)
    except Exception:
        stop()
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['start', 'stop', 'validate', 'render'])
    parser.add_argument('--settings', default='/etc/mihomo/tproxy.toml')
    args = parser.parse_args()
    try:
        if args.action in ('validate', 'render'):
            p = parameters(args.settings)
            print(render(p) if args.action == 'render' else 'TPROXY configuration is valid')
            return
        if os.geteuid() != 0:
            raise ValueError('start/stop require root')
        STATE_DIR.mkdir(mode=0o700, exist_ok=True)
        with (STATE_DIR / 'lock').open('w') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            if args.action == 'stop':
                stop()
            else:
                start(parameters(args.settings))
    except (ValueError, KeyError, OSError, yaml.YAMLError, subprocess.CalledProcessError) as error:
        print(f'mihomo-tproxy: {error}', file=sys.stderr)
        if isinstance(error, subprocess.CalledProcessError):
            print(error.stderr, file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
