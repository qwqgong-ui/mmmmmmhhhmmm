import importlib.util
from pathlib import Path
import tempfile
import unittest

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


if __name__ == '__main__':
    unittest.main()
