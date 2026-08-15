from licenselens.engine.loader import load_checks


def __getattr__(name: str):
    if name == "run_scan":
        from licenselens.engine.runner import run_scan

        return run_scan
    raise AttributeError(name)


__all__ = ["load_checks", "run_scan"]
