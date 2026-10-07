import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import json
import subprocess

spec = importlib.util.spec_from_file_location('manage', Path(__file__).parents[1] / 'manage.py')
manage = importlib.util.module_from_spec(spec)
spec.loader.exec_module(manage)


class ConfigurationTests(unittest.TestCase):
    def parameters(self, core):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'config.yaml').write_text(manage.yaml.safe_dump(core))
            for name in ('direct4.cidr', 'direct6.cidr'):
                (root / name).write_text('')
            settings = root / 'tproxy.toml'
            settings.write_text(f'''core_config = "{root / 'config.yaml'}"
direct4 = "{root / 'direct4.cidr'}"
direct6 = "{root / 'direct6.cidr'}"
proxy_mark = 358
route_table = 166
bypass_priority = 50
proxy_priority = 100
''')
            return manage.parameters(settings)

    def test_tun_is_optional(self):
        for tun in (None, {'enable': False}, {'enable': False, 'auto-redirect': True},
                    {'enable': True, 'auto-route': False, 'auto-detect-interface': False}):
            with self.subTest(tun=tun):
                core = {'tproxy-port': 17894, 'routing-mark': 666}
                if tun is not None:
                    core['tun'] = tun
                self.assertEqual(self.parameters(core)['port'], 17894)

    def test_enabled_auto_redirect_conflicts_with_tproxy(self):
        core = {'tproxy-port': 17894, 'routing-mark': 666,
                'tun': {'enable': True, 'auto-redirect': True}}
        with self.assertRaisesRegex(ValueError, 'Disable tun.auto-redirect'):
            self.parameters(core)

    def test_packaged_default_uses_pure_tproxy(self):
        core = manage.yaml.safe_load((Path(__file__).parents[1] / 'config.yaml').read_text())
        self.assertFalse(core.get('tun', {}).get('enable', False))
        self.assertEqual(self.parameters(core)['port'], core['tproxy-port'])


class DirectBypassTests(unittest.TestCase):
    def test_protected_destinations_precede_direct_sets(self):
        p = dict(bypass_mark=666, proxy_mark=358, port=17894,
                 fake4='198.18.0.0/16', fake6='2001:2::/48', direct4=['0.0.0.0/0'], direct6=['::/0'])
        rules = manage.render(p)
        self.assertLess(rules.index('system.slice/mihomo.service'), rules.index('th dport 53'))
        self.assertNotIn('systemd-resolved.service', rules)
        self.assertLess(rules.index('th dport 53'), rules.index('ip daddr @direct4'))
        self.assertLess(rules.index('ip daddr 198.18.0.0/16'), rules.index('ip daddr @direct4'))
        self.assertLess(rules.index('ip6 daddr 2001:2::/48'), rules.index('ip6 daddr @direct6'))
        self.assertIn('ip daddr @direct4 counter meta mark set 666 return', rules)

    def test_cidr_validation_and_comments(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'list'
            path.write_text('203.0.113.5/24 # direct\n\n')
            self.assertEqual(manage.cidrs(path, 4), ['203.0.113.0/24'])
            path.write_text('2001:db8::/32\n')
            with self.assertRaises(ValueError):
                manage.cidrs(path, 4)

    def test_registration_conflict_rejected_before_mutation(self):
        from unittest.mock import patch
        import subprocess
        p = dict(bypass_priority=50, proxy_priority=100, route_table=166)
        calls = []

        def fake_run(*args, **kwargs):
            calls.append(args)
            if args[0] == 'nft':
                return subprocess.CompletedProcess(args, 1, '', '')
            return subprocess.CompletedProcess(args, 0, '[{"priority":100}]', '')

        with patch.object(manage.Path, 'exists', return_value=False), patch.object(manage, 'run', fake_run):
            with self.assertRaisesRegex(ValueError, 'priority already occupied'):
                manage.start(p)
        self.assertFalse(any('add' in c or 'delete' in c for c in calls))


class InterfaceRouteTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        state = Path(self.directory.name) / 'state.json'
        self.state_patch = patch.object(manage, 'STATE', state)
        self.state_patch.start()
        self.addCleanup(self.state_patch.stop)
        self.p = dict(route_table=166, proxy_priority=100, proxy_mark=358,
                      bypass_priority=50, bypass_mark=666)
        self.routes = {('-4', 200, 77): 'unrelated'}
        self.fail_ipv6 = False

    def fake_run(self, *args, **kwargs):
        if args[:3] == ('ip', '-j', 'address'):
            return subprocess.CompletedProcess(args, 0, json.dumps(self.links), '')
        if args[0] == 'ip' and args[2] == 'route' and 'metric' in args:
            key = (args[1], int(args[args.index('table') + 1]), int(args[args.index('metric') + 1]))
            if args[3] == 'replace':
                if args[1] == '-6' and self.fail_ipv6:
                    raise subprocess.CalledProcessError(1, args, stderr='temporary link failure')
                self.routes[key] = args[args.index('dev') + 1]
            elif args[3] == 'del':
                self.routes.pop(key, None)
        return subprocess.CompletedProcess(args, 0, '', '')

    def link(self, name, index, families=('inet', 'inet6')):
        return dict(ifname=name, ifindex=index, flags=['UP'],
                    addr_info=[dict(family=family) for family in families])

    def test_refresh_handles_link_changes_and_renames(self):
        self.links = [self.link('wlan0', 3), self.link('lo', 1), self.link('eth0', 4, ())]
        self.links[1]['flags'].append('LOOPBACK')
        with patch.object(manage, 'run', side_effect=self.fake_run):
            self.assertTrue(manage.refresh_interface_routes(self.p))
            self.assertEqual(self.routes[('-4', 166, 10003)], 'wlan0')
            self.assertEqual(self.routes[('-6', 166, 10003)], 'wlan0')
            self.assertEqual(len(self.routes), 3)
            self.assertFalse(manage.refresh_interface_routes(self.p))
            self.links = [self.link('wifi0', 3)]
            self.assertTrue(manage.refresh_interface_routes(self.p))
            self.assertEqual(self.routes[('-6', 166, 10003)], 'wifi0')
            self.links = [self.link('eth0', 4, ('inet',))]
            self.assertTrue(manage.refresh_interface_routes(self.p))
            self.assertEqual(self.routes, {('-4', 200, 77): 'unrelated', ('-4', 166, 10004): 'eth0'})
            manage.stop()
            self.assertEqual(self.routes, {('-4', 200, 77): 'unrelated'})
            self.assertFalse(manage.STATE.exists())

    def test_failed_refresh_remains_owned_and_is_retried(self):
        self.links = [self.link('wlan0', 3)]
        self.fail_ipv6 = True
        with patch.object(manage, 'run', side_effect=self.fake_run):
            with self.assertRaises(subprocess.CalledProcessError):
                manage.refresh_interface_routes(self.p)
            pending = json.loads(manage.STATE.read_text())
            self.assertTrue(pending['interfaces_pending'])
            self.assertEqual(len(pending['interface_routes']), 2)
            self.fail_ipv6 = False
            self.assertTrue(manage.refresh_interface_routes(pending))
            self.assertNotIn('interfaces_pending', json.loads(manage.STATE.read_text()))
            self.assertEqual(self.routes[('-6', 166, 10003)], 'wlan0')
            manage.stop()
            self.assertEqual(self.routes, {('-4', 200, 77): 'unrelated'})

    def test_orphan_addresses_during_hotplug_are_ignored(self):
        self.links = [self.link('wlan0', 3), {'addr_info': [{'family': 'inet6'}]},
                      {'ifindex': 4, 'addr_info': [{'family': 'inet'}]},
                      {'ifindex': 4, 'ifname': 'deleted', 'addr_info': [{'family': 'inet6'}]}]
        with patch.object(manage, 'run', side_effect=self.fake_run):
            manage.refresh_interface_routes(self.p)
            self.assertEqual(self.routes, {('-4', 200, 77): 'unrelated',
                                           ('-4', 166, 10003): 'wlan0', ('-6', 166, 10003): 'wlan0'})

    def test_stop_cleans_a_partial_refresh(self):
        self.links = [self.link('wlan0', 3)]
        self.fail_ipv6 = True
        with patch.object(manage, 'run', side_effect=self.fake_run):
            with self.assertRaises(subprocess.CalledProcessError):
                manage.refresh_interface_routes(self.p)
            manage.stop()
            self.assertEqual(self.routes, {('-4', 200, 77): 'unrelated'})

    def test_failed_state_replacement_preserves_cleanup_record(self):
        manage.save_state(self.p)
        previous = manage.STATE.read_bytes()
        with patch.object(manage.Path, 'replace', side_effect=OSError('state replacement failed')):
            with self.assertRaises(OSError):
                manage.save_state(dict(self.p, interfaces_pending=True))
        self.assertEqual(manage.STATE.read_bytes(), previous)
        self.assertEqual(manage.STATE.stat().st_mode & 0o777, 0o600)


if __name__ == '__main__':
    unittest.main()
