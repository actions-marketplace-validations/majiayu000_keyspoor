import json,pathlib,subprocess,importlib.metadata,hashlib
root=pathlib.Path(__file__).resolve().parent;p=root/'manifest.json';d=json.loads(p.read_text())
cmds={
'gitleaks':(['dir','{input}','--report-format','json','--report-path','{output}','--redact','--no-banner'], 'gitleaks'),
'betterleaks':(['dir','{input}','--report-format','json','--report-path','{output}','--redact','--no-banner'], 'gitleaks'),
'kingfisher':(['scan','{input}','--no-validate','--no-update-check','--git-history','none','--format','sarif','--output','{output}','--quiet'], 'sarif'),
'titus':(['scan','{input}','--accessibility','private','--format','sarif','--output',':memory:','--quiet'], 'sarif'),
'ripsecrets':(['{input}'], 'ripsecrets'),
'leakferret':(['scan','{input}','--format','sarif','--quiet'], 'sarif'),
'detect-secrets':(['scan','--all-files','--no-verify','{input}'], 'detect_secrets'),
'deepsecrets':(['--target-dir','{input}','--outfile','{output}','--outformat','sarif','--ci','--process-count','2'], 'sarif'),
'whispers':(['{input}','--output','{output}'], 'whispers'),
'secretlint':(['{input}/**/*','--format','json','--secretlintrc',str(root/'secretlintrc.json')], 'secretlint'),
'trivy':(['fs','--scanners','secret','--offline-scan','--skip-db-update','--skip-java-db-update','--format','sarif','--output','{output}','{input}'], 'sarif'),
'trufflehog':(['filesystem','{input}','--no-verification','--no-update','--json','--fail-on-scan-errors'], 'trufflehog'),
}
for id,repo in [('detect-secrets','Yelp/detect-secrets'),('deepsecrets','ntoskernel/deepsecrets'),('whispers','Skyscanner/whispers'),('secretlint','secretlint/secretlint')]:
 exe=root/('npm/node_modules/.bin' if id=='secretlint' else 'venvs/python/bin')/id
 version=json.loads((root/'npm/node_modules/secretlint/package.json').read_text())['version'] if id=='secretlint' else subprocess.check_output([str(root/'venvs/python/bin/python'),'-c',f'import importlib.metadata;print(importlib.metadata.version({id!r}))'],text=True).strip()
 d['tools'].append(dict(id=id,status='available',version=version,source_url='https://github.com/'+repo,executable=str(exe),help_exit_code=0,accepted_exit_codes=[0,1],offline=True,install_command=f'npm install --prefix bench/tools/npm secretlint@{version} @secretlint/secretlint-rule-preset-recommend' if id=='secretlint' else f'uv pip install --python bench/tools/venvs/python/bin/python {id}=={version}'))
for t in d['tools']:
 if t['id'] in cmds:
  args,parser=cmds[t['id']];t['commands']={'fs':[t['executable']]+args};t['parser']=parser
 if t['id']=='talisman':
  t['status']='available';t.pop('reason',None);t['notes']='--help convention exits 2. Git-history-focused; pattern filesystem mode requires adapter.'
 if t['id']=='noseyparker':t['notes']='Requires scan then report with isolated datastore; adapter pending.'
 if t['status']=='available':
  c=[t['executable'],'version' if t['id'] in ['gitleaks','betterleaks','titus'] else '--version']
  r=subprocess.run(c,capture_output=True,text=True,timeout=30);t['version_command']=c;t['version_exit_code']=r.returncode;t['version_output']=(r.stdout+r.stderr).strip()[:1000]
p.write_text(json.dumps(d,indent=2)+'\n')
(root/'secretlintrc.json').write_text(json.dumps({'rules':[{'id':'@secretlint/secretlint-rule-preset-recommend'}]},indent=2)+'\n')
