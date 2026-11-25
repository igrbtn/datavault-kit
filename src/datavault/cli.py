from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .cases import CaseError, init_case, list_cases, load_case
from .gateway import GatewayConfig, ModelGateway


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="datavault")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("serve", help="run MCP server on stdio")
    n = sub.add_parser("case-new", help="create a case skeleton")
    n.add_argument("name")
    n.add_argument("--title", default="")
    n.add_argument("--description", default="")
    n.add_argument("--source", default="", help="read sources in place from this dir")
    n.add_argument("--include", nargs="*", default=[], help="file name patterns, e.g. '*.csv'")
    rn = sub.add_parser("case-rename", help="rename a case id (ids must not name the customer)")
    rn.add_argument("old")
    rn.add_argument("new")
    mk = sub.add_parser("case-mask", help="always mask a value in a case (customer name, domain)")
    mk.add_argument("name")
    mk.add_argument("type", choices=["ORG", "HOST", "PER", "ADDR", "ID", "ACC", "EMAIL", "IP"])
    mk.add_argument("value")
    cp = sub.add_parser("case-policy", help="set a policy key: k_anonymity, person_rows "
                        "(handles|deny), extract_free_fields, file_labels, column_labels")
    cp.add_argument("name")
    cp.add_argument("key")
    cp.add_argument("value")
    hd = sub.add_parser("harden",
                        help="host hardening report: perms, FileVault, hooks, LM Studio logs")
    hd.add_argument("--tighten", action="store_true", help="chmod vault home to 700/600")
    hd.add_argument("--clean-lmstudio-logs", action="store_true",
                    help="delete LM Studio server logs (they hold raw prompts)")
    rm = sub.add_parser("case-rm", help="delete a case dir (store, out/, audit, backups); sources "
                        "read in place are not touched")
    rm.add_argument("names", nargs="*")
    rm.add_argument("--auto-older-than", type=int, metavar="DAYS",
                    help="also delete auto-* cases created more than DAYS days ago")
    rm.add_argument("--yes", action="store_true",
                    help="delete; without it only shows the footprint")
    sub.add_parser("cases", help="list cases")
    sub.add_parser("check", help="model runtimes health")
    i = sub.add_parser("ingest", help="parse, detect, pseudonymize, embed a case")
    i.add_argument("case")
    i.add_argument("--no-llm", action="store_true", help="regex only, no LLM NER/columns")
    i.add_argument("--no-embed", action="store_true")
    i.add_argument("--no-ner", action="store_true",
                   help="skip per-chunk LLM NER, keep LLM column typing for tables")
    i.add_argument("--workers", type=int, default=2)
    i.add_argument("--fresh", action="store_true",
                   help="start from an empty case store (all handles are re-issued)")
    e = sub.add_parser("eval", help="leak recall against ground truth")
    e.add_argument("case")
    e.add_argument("--truth", type=Path)
    e.add_argument("--show-leaks", action="store_true",
                   help="print leaked values (synthetic cases only: prints raw data)")
    ca = sub.add_parser("call", help="call an MCP tool in-process (debug / A-B runs)")
    ca.add_argument("tool")
    ca.add_argument("args", help="JSON object with tool arguments")
    au = sub.add_parser("audit", help="heavy-model leak audit of pseudonymized chunks")
    au.add_argument("case")
    au.add_argument("--sample", type=int, default=60)
    au.add_argument("--task", default="heavy", help="model route to audit with")
    au.add_argument("--workers", type=int, default=1)
    dg = sub.add_parser("diag", help="regex rule hit counts with value shapes (no values)")
    dg.add_argument("case")
    lc = sub.add_parser("leakcheck", help="count known case values in a text file (counts only)")
    lc.add_argument("case")
    lc.add_argument("file", type=Path)
    wb = sub.add_parser("web", help="local read-only UI: calls, answers, prompt guard (loopback)")
    wb.add_argument("--port", type=int, default=8787)
    sub.add_parser("hook-file", help="Claude Code PreToolUse hook (Read|Bash): data files go "
                   "into an auto case instead of the agent's context")
    hp = sub.add_parser("hook-prompt", help="Claude Code UserPromptSubmit hook: DLP + case values")
    hp.add_argument("--text", help="scan this text instead of hook JSON on stdin")
    args = ap.parse_args(argv)

    if args.cmd == "web":
        from .web import serve
        serve(args.port)
        return 0
    if args.cmd == "hook-file":
        from .fileguard import hook_main as file_hook
        return file_hook()
    if args.cmd == "hook-prompt":
        from .promptguard import hook_main, scan
        if args.text is not None:
            v = scan(args.text)
            print(json.dumps({"decision": v.decision, "found": v.summary(),
                              "seconds": v.seconds, "masked": v.masked},
                             ensure_ascii=False, indent=1))
            return 0
        return hook_main()

    if args.cmd == "serve":
        from .server import main as serve
        serve()
        return 0
    if args.cmd == "case-new":
        try:
            c = init_case(args.name, args.title, args.description, source_dir=args.source,
                          include=args.include)
        except CaseError as e:
            print(f"error: {e}", file=sys.stderr)
            return 1
        print(f"created case {c.name}; put sources into its data/ dir")
        return 0
    if args.cmd == "case-rename":
        from .cases import rename_case
        try:
            rename_case(args.old, args.new)
        except CaseError as e:
            print(f"error: {e}", file=sys.stderr)
            return 1
        print(f"renamed {args.old} -> {args.new}")
        return 0
    if args.cmd == "case-rm":
        import time

        from .cases import case_footprint, delete_case
        names = list(args.names)
        if args.auto_older_than is not None:
            cutoff = time.time() - args.auto_older_than * 86400
            names += [c.name for c in list_cases() if c.name.startswith("auto-")
                      and c.root.stat().st_mtime < cutoff and c.name not in names]
        if not names:
            print("nothing to delete", file=sys.stderr)
            return 1
        for n in names:
            fp = delete_case(n) if args.yes else case_footprint(n)
            fp["deleted"] = bool(args.yes)
            print(json.dumps(fp, ensure_ascii=False))
        if not args.yes:
            print("dry run; add --yes to delete", file=sys.stderr)
        return 0
    if args.cmd == "case-policy":
        from .cases import set_policy
        print(json.dumps(set_policy(args.name, args.key, args.value), ensure_ascii=False))
        return 0
    if args.cmd == "harden":
        from . import harden
        out = {}
        if args.tighten:
            out["tighten"] = harden.tighten()
        if args.clean_lmstudio_logs:
            out["lmstudio_logs"] = harden.clean_lmstudio_logs()
        out["report"] = harden.report()
        print(json.dumps(out, indent=1, ensure_ascii=False))
        return 0
    if args.cmd == "case-mask":
        from .cases import add_always_mask
        n = add_always_mask(args.name, args.type, args.value)
        print(f"always_mask now has {n} entries; re-run ingest to apply")
        return 0
    if args.cmd == "cases":
        for c in list_cases():
            print(f"{c.name}\t{len(c.source_files())} sources\t{c.title}")
        return 0
    if args.cmd == "check":
        print(json.dumps(ModelGateway(GatewayConfig.load()).health(), indent=2))
        return 0
    if args.cmd == "ingest":
        from .ingest import IngestOptions, ingest
        case = load_case(args.case)
        if args.fresh:
            from .ingest import store_path
            store_path(case).unlink(missing_ok=True)
        gw = ModelGateway(GatewayConfig.load())
        opts = IngestOptions(llm=not (args.no_llm or args.no_ner), columns=not args.no_llm,
                             embed=not args.no_embed, workers=args.workers)
        rep = ingest(case, gw, opts, progress=lambda m: print(m, file=sys.stderr, flush=True))
        print(json.dumps({
            "files": rep.files, "chunks": rep.chunks, "skipped": dict(rep.skipped),
            "detections": dict(sorted(rep.detections.items())), "entities": rep.entities,
            "embedded": rep.embedded, "seconds": rep.seconds, "warnings": rep.warnings,
            "deferred": rep.deferred,
        }, indent=1, ensure_ascii=False))
        return 0
    if args.cmd == "eval":
        from .evaluate import evaluate
        case = load_case(args.case)
        if args.show_leaks and not case.description.startswith("synthetic"):
            print("error: --show-leaks only for synthetic cases", file=sys.stderr)
            return 1
        res = evaluate(case, args.truth)
        leaks = res.pop("leaks")
        fps = res.pop("fp_values")
        res["leaks"] = len(leaks)
        print(json.dumps(res, indent=1))
        if args.show_leaks:
            for t in leaks:
                print(f"LEAK {t['type']:<6} {t['file']:<28} {t['value']}")
            for t in fps:
                print(f"FP   {t['type']:<6} {t['value']}")
        return 0
    if args.cmd == "call":
        import anyio
        from mcp import Client

        from .server import build_server

        async def run():
            async with Client(build_server()) as cl:
                return await cl.call_tool(args.tool, json.loads(args.args))
        res = anyio.run(run)
        print(res.content[0].text if res.content else json.dumps(res.structured_content))
        return 0
    if args.cmd == "diag":
        import re as _re
        from collections import Counter, defaultdict

        from .detect import regex_detect
        from .ingest import store_path
        from .store import Store
        st = Store(store_path(load_case(args.case)))
        try:
            hits: Counter = Counter()
            shapes: dict[str, Counter] = defaultdict(Counter)
            for _, raw in st.chunks():
                for d in regex_detect(raw):
                    key = f"{d.source} {d.type}"
                    hits[key] += 1
                    shape = _re.sub(r"[a-z\u0430-\u044f]", "a", d.value)
                    shape = _re.sub(r"[A-Z\u0410-\u042f]", "A", _re.sub(r"\d", "9", shape))
                    shapes[key][shape[:28]] += 1
        finally:
            st.close()
        for key, n in hits.most_common():
            print(f"{n:>7}  {key:<26} {dict(shapes[key].most_common(4))}")
        return 0
    if args.cmd == "leakcheck":
        from collections import Counter

        from .ingest import store_path
        from .store import HANDLE_RE, Store
        st = Store(store_path(load_case(args.case)))
        try:
            text = args.file.read_text(encoding="utf-8", errors="replace")
            before = Counter(HANDLE_RE.findall(text))
            swept = st.build_sweeper().apply(text)
            after = Counter(HANDLE_RE.findall(swept))
            hits = after - before
            by_type = Counter(h.split(":")[1] for h in hits.elements())
        finally:
            st.close()
        print(json.dumps({"raw_values_found": sum(by_type.values()),
                          "by_type": dict(sorted(by_type.items())),
                          "handles_in_text": sum(before.values())}, indent=1))
        return 0
    if args.cmd == "audit":
        from .audit import audit
        rep = audit(load_case(args.case), ModelGateway(GatewayConfig.load()), args.sample,
                    task=args.task, workers=args.workers)
        print(json.dumps(rep, indent=1))
        print("details (with values) in the case dir: audit.json", file=sys.stderr)
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
