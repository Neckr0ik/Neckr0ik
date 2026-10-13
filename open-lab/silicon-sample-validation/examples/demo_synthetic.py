"""SYNTHETIC end-to-end demo of silicon-sample-validation.

All data are invented (see silicon_sample_validation.synthetic). The output
illustrates the workflow only and must never be presented as a result.

    python examples/demo_synthetic.py [WORKDIR]
"""

import sys

from silicon_sample_validation.demo import run_demo

if __name__ == "__main__":
    run_demo(sys.argv[1] if len(sys.argv) > 1 else None)
