"""Allow ``python3 -m crc16_en13757`` to invoke the CLI."""

from .cli import main

if __name__ == "__main__":
    import sys
    sys.exit(main())
