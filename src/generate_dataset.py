"""Generate the controlled synthetic dataset used for PrivEsc Advisor evaluation.

The dataset is balanced across 20 privilege-escalation classes (120 samples/class).
Each class has a distinct feature signature and controlled feature noise. This is a
synthetic benchmark for development/testing, not a real-world vulnerability dataset.
"""
from pathlib import Path
import numpy as np
import pandas as pd

BASE = Path(__file__).parent
OUT = BASE / "dataset" / "privesc_dataset.csv"
RANDOM_SEED = 17
FLIP_PROBABILITY = 0.079
SAMPLES_PER_CLASS = 120

FEATURES = [
    "sudo_all", "sudo_vim", "sudo_find", "sudo_python", "sudo_perl",
    "sudo_awk", "sudo_env", "sudo_nmap", "suid_bash", "suid_find",
    "suid_python", "cap_setuid", "cap_dac_override", "writable_passwd",
    "writable_sudoers", "writable_cron", "kernel_dirty_cow",
    "kernel_dirty_pipe", "vuln_pwnkit", "nfs_no_root_squash"
]

CLASSES = [
    "sudo_vim", "sudo_find", "sudo_python", "sudo_perl", "sudo_awk",
    "sudo_env", "sudo_nmap", "suid_find", "suid_bash", "suid_python",
    "cap_setuid", "cap_dac_override", "writable_passwd", "writable_sudoers",
    "writable_cron", "dirty_cow", "dirty_pipe", "pwnkit", "nfs_root_squash",
    "no_path"
]

# Four-bit signatures provide controlled co-occurrence patterns rather than
# making the label a direct copy of a single feature. The first 19 signatures
# correspond to an identifiable primary finding plus contextual indicators.
SIGNATURES = np.zeros((20, 20), dtype=np.uint8)
for i in range(19):
    SIGNATURES[i, [i, (i + 1) % 20, (i + 7) % 20, (i + 13) % 20]] = 1
# no_path remains the all-zero baseline scenario.

rng = np.random.RandomState(RANDOM_SEED)
rows = []
for class_index, label in enumerate(CLASSES):
    base = SIGNATURES[class_index]
    block = np.tile(base, (SAMPLES_PER_CLASS, 1))
    flips = rng.rand(*block.shape) < FLIP_PROBABILITY
    block = np.where(flips, 1 - block, block).astype(int)
    for row in block:
        rows.append([*row.tolist(), label])

df = pd.DataFrame(rows, columns=FEATURES + ["label"])
df.to_csv(OUT, index=False)
print(f"Wrote {len(df)} rows to {OUT}")
print(df["label"].value_counts().sort_index().to_string())
