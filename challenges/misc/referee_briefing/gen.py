#!/usr/bin/env python3
"""
referee_briefing — build-time flag generator.

Rotates both flags with a new random hex suffix and writes:

    .env       USER_FLAG and ROOT_FLAG for docker-compose
    flag.txt   Author-side copy of the two flags

Usage:
    python3 gen.py                  # random hex suffix
    python3 gen.py --hex a7f2c409   # deterministic build
"""

from __future__ import annotations

import argparse
import secrets
from pathlib import Path

HERE = Path(__file__).resolve().parent


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--hex", default=None, help="override the random hex suffix")
    args = ap.parse_args()

    rand_hex = args.hex or secrets.token_hex(4)

    user_flag = f"INFODAYS{{SaamNoLimits_mcp_tool_path_traversal_{rand_hex}}}"
    root_flag = f"INFODAYS{{SaamNoLimits_mcp_eval_sandbox_escape_root_{rand_hex}}}"

    (HERE / ".env").write_text(
        f"USER_FLAG={user_flag}\nROOT_FLAG={root_flag}\n"
    )
    (HERE / "flag.txt").write_text(f"{user_flag}\n{root_flag}\n")

    print(f"[gen] hex={rand_hex}")
    print(f"[gen] user flag -> {user_flag}")
    print(f"[gen] root flag -> {root_flag}")
    print(f"[gen] wrote {HERE}/.env and {HERE}/flag.txt")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
