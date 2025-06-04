#!/usr/bin/env python3
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from test_runner import run_basic_test

if __name__ == "__main__":
    success = run_basic_test()
    sys.exit(0 if success else 1)
