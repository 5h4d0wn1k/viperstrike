"""Allow `python -m viperstrike`."""
from viperstrike.cli import main

if __name__ == "__main__":
    # Propagate main()'s exit code like the console script does, so
    # `python -m viperstrike` fails with the same exit code as `viperstrike`.
    raise SystemExit(main())
