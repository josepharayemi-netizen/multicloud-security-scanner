import argparse,json,sys
from pathlib import Path
from scanner.engine import scan
from scanner.report import write_reports


def main():
    parser=argparse.ArgumentParser(description="Read-only multi-cloud security scanner")
    parser.add_argument("--input",type=Path,required=True)
    parser.add_argument("--output",type=Path,default=Path("reports/latest"))
    args=parser.parse_args()
    result=scan(json.loads(args.input.read_text()))
    write_reports(result,args.output)
    print(json.dumps({"score":result["security_score"],"summary":result["summary"]}))
    sys.exit(2 if result["summary"].get("CRITICAL",0) else 0)


if __name__=="__main__":
    main()
