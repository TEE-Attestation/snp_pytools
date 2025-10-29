# Copyright 2025 Hewlett Packard Enterprise Development LP.
# SPDX-License-Identifier: MIT
#
# Command-line utility for displaying AMD SEV-SNP attestation report details.

import argparse

from .attestation_report import AttestationReport
from .sev_logging import setup_cli_logging


def main():
    """
    main
    Description: Parse command-line arguments, read an attestation report file, and print its details
    Input: None (uses command-line arguments)
    Arguments:
        -f, --file: Path to the report file (default: report.bin)
        -v, --verbose: Enable verbose logging (flag)
        -q, --quiet: Enable quiet mode (flag)
        --log-file: Path to log file (optional)
    Output: None (prints attestation report details to console)
    Examples:
        python print_report.py -f report.bin
        python print_report.py -f report.bin --verbose
    """
    parser = argparse.ArgumentParser(description="Print attestation report")
    parser.add_argument(
        "-f",
        "--file",
        default="report.bin",
        help="Path to the report file (default: report.bin)",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        default=False,
        help="Enable verbose logging",
    )
    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        default=False,
        help="Enable quiet mode (warnings and errors only)",
    )
    parser.add_argument("--log-file", type=str, help="Path to log file (optional)")
    args = parser.parse_args()

    # Setup logging
    logger = setup_cli_logging(
        verbose=args.verbose, quiet=args.quiet, log_file=args.log_file
    )

    try:
        logger.info(f"Reading attestation report from: {args.file}")
        with open(args.file, "rb") as file:
            binary_data = file.read()

        logger.debug(f"Read {len(binary_data)} bytes from file")
        report = AttestationReport.unpack(binary_data)
        logger.info("Successfully parsed attestation report")

        # Log the report details
        report.log_details()

    except FileNotFoundError:
        logger.error(f"File not found: {args.file}")
        return 1
    except Exception as e:
        logger.error(f"Error processing attestation report: {e}")
        if args.verbose:
            logger.exception("Full traceback:")
        return 1

    return 0


if __name__ == "__main__":
    exit_code = main()
    exit(exit_code)
