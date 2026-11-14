from flask import Flask, render_template, request, jsonify
from parser import FeatureParser
import joblib, json, numpy as np
from pathlib import Path

app = Flask(__name__)
BASE = Path(__file__).parent
parser = FeatureParser()
meta = json.loads((BASE / 'models/model_metadata.json').read_text())
model = joblib.load(BASE / 'models/best_model.pkl')
le = joblib.load(BASE / 'models/label_encoder.pkl')

PATHS = {
    'sudo_vim': 'Sudo Vim', 'sudo_find': 'Sudo Find', 'sudo_python': 'Sudo Python',
    'sudo_perl': 'Sudo Perl', 'sudo_awk': 'Sudo Awk', 'sudo_env': 'Sudo Env',
    'sudo_nmap': 'Sudo Nmap', 'suid_find': 'SUID Find', 'suid_bash': 'SUID Bash',
    'suid_python': 'SUID Python', 'cap_setuid': 'CAP_SETUID capability abuse',
    'cap_dac_override': 'CAP_DAC_OVERRIDE → read/write protected files',
    'writable_passwd': 'Writable /etc/passwd → add lab account',
    'writable_sudoers': 'Writable /etc/sudoers', 'writable_cron': 'Writable Cron',
    'dirty_cow': 'Dirty COW (CVE-2016-5195)', 'dirty_pipe': 'Dirty Pipe (CVE-2022-0847)',
    'pwnkit': 'PwnKit (CVE-2021-4034)', 'nfs_root_squash': 'NFS no_root_squash'
}

PATH_META = {
    'sudo_vim': ('SUDO MISCONFIGURATION', 'Low', 'High', 'medium', None),
    'sudo_find': ('SUDO MISCONFIGURATION', 'Low', 'High', 'medium', None),
    'sudo_python': ('SUDO MISCONFIGURATION', 'Low', 'High', 'medium', None),
    'sudo_perl': ('SUDO MISCONFIGURATION', 'Low', 'High', 'medium', None),
    'sudo_awk': ('SUDO MISCONFIGURATION', 'Low', 'High', 'medium', None),
    'sudo_env': ('SUDO MISCONFIGURATION', 'Low', 'High', 'medium', None),
    'sudo_nmap': ('SUDO MISCONFIGURATION', 'Medium', 'High', 'medium', None),
    'suid_find': ('SUID BINARY', 'Medium', 'High', 'medium', None),
    'suid_bash': ('SUID BINARY', 'Medium', 'High', 'medium', None),
    'suid_python': ('SUID BINARY', 'Medium', 'High', 'medium', None),
    'cap_setuid': ('LINUX CAPABILITY', 'Medium', 'High', 'medium', None),
    'cap_dac_override': ('LINUX CAPABILITY', 'Medium', 'High', 'medium', None),
    'writable_passwd': ('WRITABLE FILE', 'Low', 'Low', 'low', None),
    'writable_sudoers': ('WRITABLE FILE', 'Low', 'High', 'low', None),
    'writable_cron': ('WRITABLE FILE', 'Medium', 'Medium', 'medium', None),
    'dirty_cow': ('KERNEL EXPLOIT', 'Medium', 'Medium', 'medium', 'CVE-2016-5195'),
    'dirty_pipe': ('KERNEL EXPLOIT', 'High', 'High', 'high', 'CVE-2022-0847'),
    'pwnkit': ('KERNEL / LOCAL EXPLOIT', 'Medium', 'Medium', 'high', 'CVE-2021-4034'),
    'nfs_root_squash': ('NFS MISCONFIGURATION', 'Medium', 'High', 'medium', None),
}

TRIG = {
    'dirty_cow': 'kernel_dirty_cow', 'dirty_pipe': 'kernel_dirty_pipe',
    'pwnkit': 'vuln_pwnkit', 'nfs_root_squash': 'nfs_no_root_squash'
}
TRIG.update({k: k for k in PATHS if k in meta['features']})

GUIDES = {
    'sudo_vim': {
        'description': 'The target grants sudo access to Vim, which can be abused to start a shell in an authorized lab.',
        'steps': [('Confirm the sudo rule', 'sudo -l'), ('Launch Vim through sudo', 'sudo vim'), ('Open a shell from Vim', ':!/bin/sh'), ('Verify privileges', 'id')],
        'mitigations': ['Remove unnecessary sudo access to Vim.', 'Use command-specific sudo rules and least privilege.', 'Review sudoers entries with visudo.']
    },
    'sudo_find': {
        'description': 'The target grants sudo access to find, which can invoke another program in the lab.',
        'steps': [('Confirm the sudo rule', 'sudo -l'), ('Invoke the permitted binary', 'sudo find . -exec /bin/sh \\; -quit'), ('Verify privileges', 'id')],
        'mitigations': ['Remove unnecessary sudo permission for find.', 'Restrict sudo commands to narrowly defined arguments.', 'Review sudoers regularly.']
    },
    'sudo_python': {
        'description': 'Sudo permission for Python allows the interpreter to execute commands with elevated privileges.',
        'steps': [('Confirm the sudo rule', 'sudo -l'), ('Start a shell through the interpreter', "sudo python3 -c 'import os; os.execl(\"/bin/sh\",\"sh\")'"), ('Verify privileges', 'id')],
        'mitigations': ['Avoid granting unrestricted sudo access to interpreters.', 'Use a dedicated wrapper with fixed arguments.', 'Apply least privilege in sudoers.']
    },
    'sudo_perl': {
        'description': 'Sudo permission for Perl can be used to execute commands with the permitted privilege level.',
        'steps': [('Confirm the sudo rule', 'sudo -l'), ('Start a shell through Perl', "sudo perl -e 'exec \"/bin/sh\"'"), ('Verify privileges', 'id')],
        'mitigations': ['Remove unrestricted sudo access to Perl.', 'Use fixed-purpose scripts instead of interpreters.', 'Audit sudoers entries.']
    },
    'sudo_awk': {
        'description': 'Sudo access to awk can permit command execution from the interpreter.',
        'steps': [('Confirm the sudo rule', 'sudo -l'), ('Start a shell through awk', "sudo awk 'BEGIN {system(\"/bin/sh\")}'"), ('Verify privileges', 'id')],
        'mitigations': ['Remove unnecessary sudo access to awk.', 'Restrict commands and arguments.', 'Follow least privilege.']
    },
    'sudo_env': {
        'description': 'Sudo access to env can allow execution of another program with the permitted privilege.',
        'steps': [('Confirm the sudo rule', 'sudo -l'), ('Launch a shell through env', 'sudo env /bin/sh'), ('Verify privileges', 'id')],
        'mitigations': ['Remove unrestricted sudo permission for env.', 'Use fixed commands rather than general-purpose utilities.', 'Audit sudoers configuration.']
    },
    'sudo_nmap': {
        'description': 'Some older nmap versions provide interactive functionality that can be abused when nmap is allowed through sudo.',
        'steps': [('Confirm the sudo rule', 'sudo -l'), ('Check the installed version', 'nmap --version'), ('Use the interactive interface if supported', 'sudo nmap --interactive'), ('Request a shell from the prompt', '!sh'), ('Verify privileges', 'id')],
        'mitigations': ['Do not grant unrestricted sudo access to nmap.', 'Upgrade old nmap versions.', 'Use narrowly scoped administrative wrappers.']
    },
    'suid_find': {
        'description': 'A SUID find binary may execute another program with elevated effective privileges.',
        'steps': [('Confirm SUID permission', 'ls -l $(which find)'), ('Invoke the privileged shell', 'find . -exec /bin/sh -p \\; -quit'), ('Verify privileges', 'id')],
        'mitigations': ['Remove unnecessary SUID permission.', 'Replace SUID utilities with narrowly scoped privileged helpers.', 'Audit SUID/SGID binaries periodically.']
    },
    'suid_bash': {
        'description': 'A SUID bash binary can start a shell while preserving elevated effective privileges.',
        'steps': [('Confirm SUID permission', 'ls -l /bin/bash'), ('Start bash in privileged mode', '/bin/bash -p'), ('Verify privileges', 'id')],
        'mitigations': ['Remove the SUID bit from bash.', 'Audit SUID binaries.', 'Use dedicated privileged programs instead of SUID shells.']
    },
    'suid_python': {
        'description': 'A SUID Python interpreter can execute commands with elevated effective privileges.',
        'steps': [('Confirm SUID permission', 'ls -l $(which python3)'), ('Start a shell through Python', "python3 -c 'import os; os.execl(\"/bin/sh\",\"sh\")'"), ('Verify privileges', 'id')],
        'mitigations': ['Remove SUID from Python.', 'Do not deploy interpreters as SUID binaries.', 'Audit SUID files regularly.']
    },
    'cap_setuid': {
        'description': 'An executable with cap_setuid+ep can change its effective UID and may lead to privilege escalation.',
        'steps': [('Find file capabilities', 'getcap -r / 2>/dev/null'), ('Verify the selected binary', 'getcap /path/to/binary'), ('Use the vulnerable interpreter in the lab', "python3 -c 'import os; os.setuid(0); os.execl(\"/bin/sh\",\"sh\")'"), ('Verify privileges', 'id')],
        'mitigations': ['Remove unnecessary cap_setuid capabilities.', 'Grant capabilities only to dedicated binaries.', 'Audit file capabilities with getcap.']
    },
    'cap_dac_override': {
        'description': 'cap_dac_override can bypass normal discretionary file permission checks for a capable executable.',
        'steps': [('Find file capabilities', 'getcap -r / 2>/dev/null'), ('Inspect the selected binary', 'getcap /path/to/binary'), ('Test access to a harmless protected lab file', 'ls -l /path/to/test-file'), ('Document the access result', 'id')],
        'mitigations': ['Remove unnecessary cap_dac_override.', 'Use dedicated service accounts and file permissions.', 'Audit capabilities on executable files.']
    },
    'writable_passwd': {
        'description': 'Write access to /etc/passwd can allow unauthorized account changes on a vulnerable lab system.',
        'steps': [('Confirm the permission', 'ls -l /etc/passwd'), ('Back up the file', 'cp /etc/passwd /tmp/passwd.bak'), ('Create a lab-only password hash', "openssl passwd -6 'LabPassword123!'"), ('Edit the file using a temporary lab account', 'sudoedit /etc/passwd'), ('Verify the test account', 'id <test-user>')],
        'mitigations': ['Ensure /etc/passwd is owned by root and not writable by unprivileged users.', 'Review file permissions and ACLs.', 'Monitor unexpected changes to account databases.']
    },
    'writable_sudoers': {
        'description': 'Write access to sudoers configuration can allow unauthorized privilege changes.',
        'steps': [('Locate the writable sudoers file', 'ls -l /etc/sudoers /etc/sudoers.d/* 2>/dev/null'), ('Back up the lab file', 'cp /path/to/sudoers-file /tmp/sudoers.bak'), ('Add a temporary lab-only rule', 'echo "<lab-user> ALL=(ALL) NOPASSWD:ALL" >> /path/to/sudoers-file'), ('Validate syntax', 'visudo -c'), ('Verify the authorization', 'sudo -l')],
        'mitigations': ['Make sudoers files root-owned and non-writable by unprivileged users.', 'Validate changes with visudo.', 'Restrict administrative write access.']
    },
    'writable_cron': {
        'description': 'A root-run cron job that executes a user-writable script creates a privilege escalation path.',
        'steps': [('Identify the root-run cron entry', 'grep -R "cron-logrotate\\|/path/to/script" /etc/cron* /var/spool/cron 2>/dev/null'), ('Confirm the script is writable', 'ls -l /path/to/script'), ('Back up the script', 'cp /path/to/script /tmp/script.bak'), ('Insert a harmless lab marker', "echo 'echo CRON_TEST > /tmp/privesc_cron_test' >> /path/to/script"), ('Verify scheduled execution', 'cat /tmp/privesc_cron_test'), ('Restore the original script', 'cp /tmp/script.bak /path/to/script')],
        'mitigations': ['Make root-run scripts root-owned and non-writable by unprivileged users.', 'Review cron jobs and their called scripts.', 'Use integrity monitoring for privileged scripts.']
    },
    'dirty_cow': {
        'description': 'Dirty COW is a historical Linux kernel race-condition vulnerability affecting vulnerable kernels.',
        'steps': [('Confirm the kernel', 'uname -r'), ('Search for a verified lab PoC', 'searchsploit Dirty COW'), ('Copy the selected PoC', 'searchsploit -m 40839'), ('Compile the PoC', 'gcc -pthread dirty.c -o dirty -lcrypt'), ('Run in the isolated lab', './dirty'), ('Verify privileges', 'id')],
        'mitigations': ['Update the Linux kernel to a patched release.', 'Apply vendor security updates.', 'Remove unsupported operating systems from production.']
    },
    'dirty_pipe': {
        'description': 'Dirty Pipe is a Linux kernel vulnerability affecting specific kernel versions and file-cache handling.',
        'steps': [('Confirm the kernel', 'uname -r'), ('Search for a verified lab PoC', 'searchsploit Dirty Pipe'), ('Review the selected PoC', 'less dirty-pipe.c'), ('Compile according to the verified PoC', 'gcc dirty-pipe.c -o dirty-pipe'), ('Run only on the vulnerable lab VM', './dirty-pipe'), ('Verify the result', 'id')],
        'mitigations': ['Update to a vendor-patched kernel.', 'Apply security updates promptly.', 'Track kernel versions on managed systems.']
    },
    'pwnkit': {
        'description': 'PwnKit (CVE-2021-4034) affects vulnerable polkit/pkexec installations and can provide local privilege escalation.',
        'steps': [('Check pkexec', 'pkexec --version'), ('Search for a verified lab PoC', 'searchsploit PwnKit'), ('Compile the selected C PoC', 'gcc cve-2021-4034-poc.c -o poc'), ('Run in the isolated lab', './poc'), ('Verify privileges', 'id')],
        'mitigations': ['Patch polkit immediately.', 'Apply vendor security updates.', 'Remove or restrict vulnerable packages where appropriate.']
    },
    'nfs_root_squash': {
        'description': 'An NFS export with no_root_squash may allow root privileges from an authorized client to affect exported files.',
        'steps': [('Inspect exports', 'showmount -e <target-ip>'), ('Mount the lab export', 'sudo mount -t nfs <target-ip>:/export /mnt/lab-nfs'), ('Create a harmless test file', 'sudo touch /mnt/lab-nfs/privesc_test'), ('Check ownership', 'ls -l /mnt/lab-nfs/privesc_test'), ('Remove the test artifact', 'sudo rm /mnt/lab-nfs/privesc_test')],
        'mitigations': ['Use root_squash on NFS exports.', 'Restrict export networks and hosts.', 'Review NFS export permissions regularly.']
    }
}


def risk(x):
    score = sum(18 for f in ['sudo_all','writable_passwd','writable_sudoers','kernel_dirty_cow','kernel_dirty_pipe','vuln_pwnkit'] if x.get(f))
    score += sum(10 for f in ['cap_setuid','cap_dac_override','writable_cron','nfs_no_root_squash'] if x.get(f))
    score += sum(5 for f in x if f.startswith('sudo_') and x[f])
    score += sum(4 for f in x if f.startswith('suid_') and x[f])
    score = min(100, score)
    return {'score': score, 'label': 'LOW' if score < 25 else 'MEDIUM' if score < 50 else 'HIGH' if score < 75 else 'CRITICAL'}


def shap_values(a, predicted_index):
    """Return real SHAP feature attribution for the fitted model.

    The saved best model is a sklearn Pipeline for Logistic Regression
    (StandardScaler -> LogisticRegression).  SHAP must explain the fitted
    estimator with the same scaled feature matrix, not the Pipeline object
    itself.  Random Forest is handled with TreeExplainer.
    """
    features = meta['features']
    try:
        import shap

        # Logistic Regression pipeline
        if hasattr(model, 'named_steps') and 'model' in model.named_steps:
            estimator = model.named_steps['model']
            scaler = model.named_steps.get('scale')
            if hasattr(estimator, 'coef_'):
                background = np.zeros((1, len(features)), dtype=float)
                x_scaled = scaler.transform(a) if scaler is not None else a
                bg_scaled = scaler.transform(background) if scaler is not None else background
                explainer = shap.LinearExplainer(estimator, bg_scaled)
                sv = explainer(x_scaled).values
                if sv.ndim == 3:
                    values = sv[0, :, predicted_index]
                elif sv.ndim == 2:
                    # Binary LinearExplainer can return one value column.
                    values = sv[0]
                else:
                    values = np.asarray(sv).reshape(-1)
                pairs = [
                    {'feature': f, 'value': float(v)}
                    for f, v in zip(features, values)
                ]
                return sorted(pairs, key=lambda z: abs(z['value']), reverse=True)[:8]

        # Plain linear estimator fallback
        if hasattr(model, 'coef_'):
            background = np.zeros((1, len(features)), dtype=float)
            explainer = shap.LinearExplainer(model, background)
            sv = explainer(a).values
            if sv.ndim == 3:
                values = sv[0, :, predicted_index]
            else:
                values = sv[0]
            pairs = [{'feature': f, 'value': float(v)} for f, v in zip(features, values)]
            return sorted(pairs, key=lambda z: abs(z['value']), reverse=True)[:8]

        # Random Forest / tree model
        explainer = shap.TreeExplainer(model)
        sv = explainer.shap_values(a)
        if isinstance(sv, list):
            values = np.asarray(sv[predicted_index])[0]
        else:
            sv = np.asarray(sv)
            if sv.ndim == 3:
                values = sv[0, :, predicted_index]
            elif sv.ndim == 2:
                values = sv[0]
            else:
                values = sv.reshape(-1)
        pairs = [{'feature': f, 'value': float(v)} for f, v in zip(features, values)]
        return sorted(pairs, key=lambda z: abs(z['value']), reverse=True)[:8]

    except Exception as exc:
        # Keep the error out of the user-facing UI, but print it to the
        # Flask console so a developer can diagnose SHAP installation/API issues.
        print('SHAP calculation error:', repr(exc))
        return []


@app.route('/')
def index():
    return render_template('index.html', meta=meta)


@app.post('/api/analyze')
def analyze():
    try:
        raw = (request.json or {}).get('raw_text', '')
        parsed = parser.parse(raw)
        x = parsed['features']
        a = np.array([[x[f] for f in meta['features']]], dtype=float)
        probs = model.predict_proba(a)[0]
        pred_index = int(np.argmax(probs))

        candidates = []
        model_classes = list(le.classes_)
        for i, probability in enumerate(probs):
            if i >= len(model_classes):
                continue
            cid = model_classes[i]
            if cid == 'no_path' or cid not in PATHS:
                continue
            trigger = TRIG.get(cid)
            detected = bool(trigger and x.get(trigger))
            evidence_score = 0.95 if detected else 0.55
            score = min(1.0, 0.70 * float(probability) + 0.30 * evidence_score)
            category, detection, complexity, novelty, cve = PATH_META.get(cid, ('PRIVESC PATH', 'Medium', 'Medium', 'medium', None))
            guide = GUIDES.get(cid, {'description': 'Verify the finding manually on the authorized lab target.', 'steps': [], 'mitigations': ['Validate and remediate the underlying configuration.']})
            candidates.append({
                'id': cid, 'class_index': int(i), 'name': PATHS[cid], 'probability': float(probability), 'score': score,
                'evidence': trigger if detected else None, 'category': category,
                'detection': detection, 'complexity': complexity, 'novelty': novelty,
                'cve': cve, 'description': guide['description'], 'steps': guide['steps'],
                'mitigations': guide['mitigations']
            })

        candidates.sort(key=lambda r: r['score'], reverse=True)
        recommendations = []
        for item in candidates[:5]:
            item['rank'] = len(recommendations) + 1
            # Explain this recommendation's own class, not the single overall
            # predicted class. This prevents every card reusing the same SHAP list.
            item['shap'] = shap_values(a, item['class_index'])
            # Keep the class this explanation belongs to for debugging/verification.
            item['shap_for_class'] = item['id']
            item.pop('class_index', None)  # internal detail; not needed by the UI
            recommendations.append(item)

        global_shap = shap_values(a, pred_index)
        return jsonify({
            'success': True,
            'features': x,
            'active_features': [f for f, v in x.items() if v],
            'metadata': parsed['metadata'],
            'risk': risk(x),
            'recommendations': recommendations,
            'shap': global_shap,
            'top_k': 5,
            'model': meta.get('best_model'),
            'dataset_rows': meta.get('dataset_rows', 0),
            'class_count': len(meta.get('classes', [])),
            'cv_folds': meta.get('cv_folds', 0),
            'cv_results': meta.get('cv_results', {}),
            'evaluation_results': meta.get('results', {})
        })
    except Exception as exc:
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(exc)}), 500


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=True)
