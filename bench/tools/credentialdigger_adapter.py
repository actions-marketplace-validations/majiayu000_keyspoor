#!/usr/bin/env python3
"""Offline upstream SDK, official bundled rules, fresh in-memory SQLite database."""
import contextlib,json,pathlib,sys
from credentialdigger import SqliteClient
root=pathlib.Path(__file__).resolve().parent
path=str(pathlib.Path(sys.argv[1]).resolve())
with contextlib.redirect_stdout(sys.stderr):
 client=SqliteClient(':memory:')
 client.add_rules_from_file(str(root/'source/credential-digger/ui/backend/rules.yml'))
 client.scan_path(path,models=None,debug=False,similarity=False)
 discoveries=client.get_discoveries(path)
findings=[{'path':x['file_name'],'line':x['line_number'],'rule_id':str(x['rule_id'])} for x in discoveries]
print(json.dumps({'complete':True,'findings':findings}))
