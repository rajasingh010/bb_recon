#!/bin/bash
echo "🐛 Bug Bounty Recon Tool - Kali Linux Edition"
echo "=============================================="
echo ""
echo "Installing dependencies..."
pip3 install -r requirements.txt
echo ""
echo "Starting Bug Bounty Scanner..."
python3 bb_scanner.py
