"""python -m reversi_sdk verify LEDGER.jsonl"""
import sys

from .ledger import verify_file


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 2 or argv[0] != "verify":
        print("usage: python -m reversi_sdk verify LEDGER.jsonl", file=sys.stderr)
        return 64
    r = verify_file(argv[1])
    if r.ok:
        print(f"ok: {r.records} records, head {r.head}")
        return 0
    print(f"TAMPERED or corrupt at record {r.seq}: {r.error}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
