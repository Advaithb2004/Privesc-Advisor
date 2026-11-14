import re

FEATURES = [
    'sudo_all', 'sudo_vim', 'sudo_find', 'sudo_python', 'sudo_perl',
    'sudo_awk', 'sudo_env', 'sudo_nmap', 'suid_bash', 'suid_find',
    'suid_python', 'cap_setuid', 'cap_dac_override', 'writable_passwd',
    'writable_sudoers', 'writable_cron', 'kernel_dirty_cow',
    'kernel_dirty_pipe', 'vuln_pwnkit', 'nfs_no_root_squash'
]

class FeatureParser:
    def parse(self, text):
        low = (text or '').lower()
        x = {f: 0 for f in FEATURES}
        sudos, suids, caps = [], [], []

        # Sudo rules / allowed binaries
        for b in ['vim', 'find', 'python', 'perl', 'awk', 'env', 'nmap']:
            if re.search(r'(sudo|nopasswd|all).*?\b' + re.escape(b) + r'\b', low, re.S):
                x['sudo_' + b] = 1
                sudos.append(b)

        if re.search(r'\(all.*?all\)|nopasswd:\s*all', low, re.S):
            x['sudo_all'] = 1

        # Common SUID binaries
        for b in ['bash', 'find', 'python']:
            if re.search(r'suid.*?\b' + re.escape(b) + r'\b|/usr/bin/' + re.escape(b) + r'.*?\+s|-rws.*?\b' + re.escape(b) + r'\b', low, re.S):
                x['suid_' + b] = 1
                suids.append(b)

        # Linux capabilities
        if 'cap_setuid' in low or 'setuid+ep' in low:
            x['cap_setuid'] = 1
            caps.append('cap_setuid')
        if 'cap_dac_override' in low:
            x['cap_dac_override'] = 1
            caps.append('cap_dac_override')

        # Writable files / jobs
        if re.search(r'writable.*?/etc/passwd|/etc/passwd.*writable', low, re.S):
            x['writable_passwd'] = 1
        if re.search(r'writable.*?/etc/sudoers|/etc/sudoers.*writable', low, re.S):
            x['writable_sudoers'] = 1
        if re.search(r'writable.*cron|cron.*writable', low, re.S):
            x['writable_cron'] = 1

        if 'no_root_squash' in low:
            x['nfs_no_root_squash'] = 1

        # Kernel version
        m = re.search(r'\b(\d+)\.(\d+)\.(\d+)', low)
        if m:
            v = tuple(map(int, m.groups()))
            if v < (4, 8, 3):
                x['kernel_dirty_cow'] = 1
            if (5, 8, 0) <= v <= (5, 16, 11):
                x['kernel_dirty_pipe'] = 1

        # Explicit vulnerability names / CVEs
        if 'dirty cow' in low or 'cve-2016-5195' in low:
            x['kernel_dirty_cow'] = 1
        if 'dirty pipe' in low or 'cve-2022-0847' in low:
            x['kernel_dirty_pipe'] = 1
        if 'pwnkit' in low or 'cve-2021-4034' in low:
            x['vuln_pwnkit'] = 1

        return {
            'features': x,
            'metadata': {
                'detected_sudos': sudos,
                'detected_suids': suids,
                'detected_caps': caps
            }
        }
