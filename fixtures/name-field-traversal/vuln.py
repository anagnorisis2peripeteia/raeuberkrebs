import os


# PLANTED LEAD (CWE-22, name-field traversal): `backup_name` is treated as an opaque identifier and
# joined to the workspace base with NO single-component check — but `os.path.join` still honours `..`
# and an absolute value discards the base. `backup_name = "../../etc/passwd"` reads outside the
# workspace; `backup_name = "/etc/shadow"` replaces the base entirely. Intentional — the name-field
# traversal static lane surfaces this as a lead. The safe form validates the field to a single normal
# component (reject `..`, absolute, separators) or canonicalizes + asserts it stays under the base.
def restore_backup(base, backup_name):
    path = os.path.join(base, backup_name)
    with open(path) as f:
        return f.read()
