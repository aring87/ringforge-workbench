import argparse
from static_triage_engine.engine import run_case

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("sample")
    ap.add_argument("--case", default=None)
    ap.add_argument("--no-progress", action="store_true")
    args = ap.parse_args()

    r = run_case(args.sample, case_name=args.case, show_progress=(not args.no_progress))
    print(f"[+] Case: {r['case_dir']}")
    print(f"[+] report.md: {r.get('report_md')}")
    print(f"[+] report.html: {r.get('report_html')}")
    print(f"[+] report.pdf: {r.get('report_pdf')}")
    print(f"[+] total runtime: {r.get('runtime_sec_total')}s")
    print(f"[+] SOC verdict: {r.get('verdict')} (score={r.get('risk_score')}/100)")

if __name__ == "__main__":
    main()
