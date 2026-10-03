#!/usr/bin/env python3
"""Parse upstream filesystem JSON while excluding raw matched values."""
import json,pathlib,subprocess,sys
exe=pathlib.Path(__file__).resolve().parent/'source/rusty-hog-build/target/release/duroc_hog'
r=subprocess.run([str(exe),sys.argv[1]],capture_output=True,text=True)
if r.returncode:
 sys.stderr.write(r.stderr);sys.exit(r.returncode)
# The upstream CLI can log an error yet exit zero. Missing/invalid JSON is a
# failed scan, never a clean result.
data=json.loads(r.stdout)
if not isinstance(data,list):raise ValueError('Expected upstream findings array')
print(json.dumps({'complete':True,'findings':[{'path':x['path'],'line':x['linenum'],'rule_id':x['reason']} for x in data]}))
