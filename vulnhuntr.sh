#!/bin/bash
# Script to run vulnhuntr with the virtual environment

# Navigate to project directory
cd "$(dirname "$0")"

# Activate virtual environment and run vulnhuntr
.venv/bin/vulnhuntr "$@"
