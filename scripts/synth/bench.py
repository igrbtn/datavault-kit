"""Generate synthetic cases for several seeds, ingest, evaluate; print a summary.

Usage: DATAVAULT_HOME=<scratch> python scripts/synth/bench.py --seeds 7 11 23 [--no-llm]
Leaked/unrelated values are printed only with --show (synthetic data, safe to view).
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import gen_synthetic  # noqa: E402

from datavault.cases import CaseError, load_case  # noqa: E402
from datavault.evaluate import evaluate  # noqa: E402
from datavault.gateway import GatewayConfig, ModelGateway  # noqa: E402
from datavault.ingest import IngestOptions, ingest, store_path  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seeds", type=int, nargs="+", default=[7, 11, 23])
    ap.add_argument("--no-llm", action="store_true")
    ap.add_argument("--show", action="store_true")
    ap.add_argument("--prefix", default="bench")
    a = ap.parse_args()
    gw = ModelGateway(GatewayConfig.load())
    for seed in a.seeds:
        name = f"{a.prefix}-s{seed}"
        try:
            case = load_case(name)
        except CaseError:
            gen_synthetic.main([name, "--seed", str(seed)])
            case = load_case(name)
        store_path(case).unlink(missing_ok=True)
        rep = ingest(case, gw, IngestOptions(llm=not a.no_llm, columns=not a.no_llm,
                                             embed=False))
        r = evaluate(case)
        weak = {k: (v["recall"], v["total"]) for k, v in r["by_type"].items() if v["recall"] < 1}
        print(f"{name}: hard={r['recall_hard']} all={r['recall_all']} "
              f"values={r['extracted_values']} unrelated={r['unrelated_values']} "
              f"weak={weak} t={rep.seconds}s")
        if a.show:
            for t in r["leaks"]:
                print(f"  LEAK {t['type']:<6} {t['file']:<26} {t['value']}")
            for t in r["fp_values"]:
                print(f"  FP   {t['type']:<6} {t['value']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
