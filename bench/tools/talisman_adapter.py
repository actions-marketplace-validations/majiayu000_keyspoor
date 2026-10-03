#!/usr/bin/env python3
"""Upstream git scan; preserve file-only findings without inventing line locations."""
import json,pathlib,subprocess,sys,tempfile
root=pathlib.Path(__file__).resolve().parent
mode,repo=sys.argv[1:3]
if mode == "staged":
 result=subprocess.run([str(root/"binaries/talisman"),"--githook","pre-commit"],cwd=repo,capture_output=True,text=True)
 if result.returncode not in (0,1):
  sys.stderr.write(result.stderr);sys.exit(result.returncode)
 names=subprocess.check_output(["git","diff","--cached","--name-only","-z"],cwd=repo).decode().split("\0")
 visible={line.split("|")[1].strip() for line in result.stdout.splitlines() if line.startswith("|") and len(line.split("|"))>2}
 findings=[{"path":name} for name in names if name and name in visible]
 if result.returncode == 1 and not findings:
  sys.stderr.write("Talisman reported failure but no staged path could be normalized\n");sys.exit(3)
 print(json.dumps({"complete":True,"location_precision":"file","findings":findings,"upstream_exit_code":result.returncode}))
 sys.exit(result.returncode)
with tempfile.TemporaryDirectory(prefix='talisman-benchmark-') as temp:
 result=subprocess.run([str(root/'binaries/talisman'),'--scan','--reportDirectory',temp],cwd=repo,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
 if result.returncode not in (0,1):
  sys.stderr.buffer.write(result.stderr);sys.exit(result.returncode)
 report=pathlib.Path(temp)/'talisman_reports/data/report.json'
 if not report.exists():
  sys.stderr.buffer.write(result.stderr);sys.exit(3)
 data=json.loads(report.read_text())
 findings=[]
 for file in data['results']:
  for category in ['failure_list','warning_list']:
   for f in file.get(category,[]):
    findings.append({'path':file['filename'],'category':f['type'],'commits':f.get('commits',[]),'severity':f.get('severity'),'kind':category})
 print(json.dumps({'complete':True,'location_precision':'file','findings':findings,'upstream_exit_code':result.returncode}))
 sys.exit(result.returncode)
