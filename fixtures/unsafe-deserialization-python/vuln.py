import pickle

# PLANTED VULNERABILITY (pickle.loads on attacker bytes): unpickling executes the payload's
# __reduce__, so attacker-controlled bytes run arbitrary code. Intentional — exists so the
# Raeuberkrebs unsafe-deserialization Python lane can prove itself live. Standard-library only, so the
# canary fires without any third-party dependency installed.
def load_pickle(data):
    return pickle.loads(data)


# PLANTED VULNERABILITY (yaml.load with an unsafe loader): the loader constructs arbitrary Python
# objects from the document. `yaml` is imported lazily so this fixture module still loads (and the
# pickle canary still fires) on a machine without PyYAML installed. Intentional.
def load_yaml(text):
    import yaml

    return yaml.load(text, Loader=yaml.UnsafeLoader)
