from pathlib import Path
import subprocess
import tempfile
import unittest


class InstallMigrationTests(unittest.TestCase):
    def migration(self, pacsave):
        script = (Path(__file__).parents[1] / 'mihomo.install').read_text()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for path in ('etc/mihomo', 'run', 'usr/lib/mihomo-tproxy'):
                (root / path).mkdir(parents=True)
            filename = 'config.yaml.pacsave' if pacsave else 'config.yaml'
            previous = root / 'etc/mihomo' / filename
            previous.write_text('original-user-config\n')
            previous.chmod(0o600)
            helper = root / 'usr/lib/mihomo-tproxy/manage'
            helper.write_text('#!/bin/bash\nexit 0\n')
            helper.chmod(0o755)
            for prefix in ('/etc/', '/run/', '/usr/'):
                script = script.replace(prefix, str(root) + prefix)
            script += f'''\n
systemctl() {{ return 0; }}
pre_install || exit 1
printf 'new-package-default\\n' > '{root}/etc/mihomo/config.yaml'
chmod 644 '{root}/etc/mihomo/config.yaml'
post_install || exit 1
'''
            subprocess.run(['bash', '-e', '-c', script], check=True)
            result = root / 'etc/mihomo/config.yaml'
            self.assertEqual(result.read_text(), 'original-user-config\n')
            self.assertEqual(result.stat().st_mode & 0o777, 0o600)

    def test_upgrade_preserves_contents_and_permissions(self):
        self.migration(pacsave=False)

    def test_replacing_mihomo_bin_restores_pacsave(self):
        self.migration(pacsave=True)
