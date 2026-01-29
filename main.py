#!/usr/bin/env python3
"""
SecurePass - Main Entry Point
Intelligent Password Security Analyzer
"""

import sys


def main():
    """Main entry point that routes to CLI or GUI."""
    # Check if --gui flag is present
    if '--gui' in sys.argv:
        sys.argv.remove('--gui')
        from securepass.gui import main as gui_main
        gui_main()
    else:
        from securepass.cli import main as cli_main
        cli_main()


if __name__ == '__main__':
    main()
