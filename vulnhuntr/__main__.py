"""CLI entry point. Loads .env, configures logging, runs analysis."""

from __future__ import annotations

import logging
import sys

import dotenv
import structlog

# Load environment variables from .env file
dotenv.load_dotenv()

# Configure structured logging
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
        structlog.processors.JSONRenderer(),
    ],
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    wrapper_class=structlog.stdlib.BoundLogger,
    cache_logger_on_first_use=True,
)


def main() -> int:
    """Main entry point for Vulnhuntr CLI.

    Returns:
        Exit code (0 for success, non-zero for errors)
    """
    from vulnhuntr.cli.parser import (
        create_argument_parser,
        normalize_args,
        validate_args,
    )
    from vulnhuntr.cli.runner import run_analysis

    # Parse command line arguments
    parser = create_argument_parser()
    args = parser.parse_args()

    # Validate arguments
    error = validate_args(args)
    if error:
        parser.error(error)
        return 1

    # Normalize paths
    args = normalize_args(args)

    # Configure logging level based on verbosity flags
    if args.verbosity >= 2:
        log_level = logging.DEBUG
    elif args.verbosity == 1:
        log_level = logging.INFO
    else:
        log_level = logging.WARNING
    logging.basicConfig(level=log_level, format="%(message)s")
    logging.getLogger().setLevel(log_level)

    # Run the analysis
    try:
        return run_analysis(args)
    except KeyboardInterrupt:
        print("\n\nAnalysis interrupted by user.")
        return 130
    except Exception as e:
        log = structlog.get_logger()
        log.error("Unhandled exception", error=str(e), exc_info=True)
        print(f"\nError: {e}")
        return 1


def run():
    """Legacy entry point for backward compatibility."""
    sys.exit(main())


if __name__ == "__main__":
    sys.exit(main())
