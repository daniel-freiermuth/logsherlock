#!/usr/bin/env python3
"""Write the LogCrab Homebrew formula for a published release."""

from __future__ import annotations

import argparse
import re
from pathlib import Path


SEMVER_PATTERN = re.compile(
    r"^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)"
    r"(?:-(?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*))*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)
SHA256_PATTERN = re.compile(r"^[0-9a-fA-F]{64}$")


def semver(value: str) -> str:
    if not SEMVER_PATTERN.fullmatch(value):
        raise argparse.ArgumentTypeError("must be a Semantic Version, e.g. 1.2.3")
    return value


def sha256(value: str) -> str:
    if not SHA256_PATTERN.fullmatch(value):
        raise argparse.ArgumentTypeError("must be a 64-character hexadecimal SHA-256")
    return value.lower()

def main() -> None:
    parser = argparse.ArgumentParser(description="Write the LogCrab Homebrew formula.")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--version", required=True, type=semver)
    parser.add_argument("--arm-sha256", required=True, type=sha256)
    parser.add_argument("--intel-sha256", required=True, type=sha256)
    args = parser.parse_args()

    release_url = f"https://github.com/daniel-freiermuth/logcrab/releases/download/v{args.version}"
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        f'''class Logcrab < Formula
  desc "High-performance log file viewer"
  homepage "https://github.com/daniel-freiermuth/logcrab"
  version "{args.version}"

  on_macos do
    on_arm do
      url "{release_url}/logcrab_aarch64_macos.tar.gz"
      sha256 "{args.arm_sha256}"
    end

    on_intel do
      url "{release_url}/logcrab_x86_64_macos.tar.gz"
      sha256 "{args.intel_sha256}"
    end
  end

  on_linux do
    odie "LogCrab has no Linux Homebrew release archive"
  end

  def install
    bin.install "logcrab"
  end
end
'''
    )


if __name__ == "__main__":
    main()
