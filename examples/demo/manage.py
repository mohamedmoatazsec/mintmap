#!/usr/bin/env python
"""Teahouse: the MintMap demo project. MintMap only parses this code; Django does not need to be installed."""
import os
import sys

if __name__ == "__main__":
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "teahouse.settings")
    from django.core.management import execute_from_command_line

    execute_from_command_line(sys.argv)
