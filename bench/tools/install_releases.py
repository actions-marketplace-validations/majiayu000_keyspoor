import urllib.request,json,concurrent.futures,pathlib,tarfile,zipfile,hashlib,os
root=pathlib.Path(__file__).resolve().parent
specs=[('gitleaks','gitleaks/gitleaks','darwin_arm64.tar.gz','gitleaks'),('trufflehog','trufflesecurity/trufflehog','darwin_arm64.tar.gz','trufflehog'),('kingfisher','mongodb/kingfisher','darwin-arm64.tgz','kingfisher'),('betterleaks','betterleaks/betterleaks','darwin_arm64.tar.gz','betterleaks'),('titus','praetorian-inc/titus','titus-darwin-arm64','titus'),('ripsecrets','sirwart/ripsecrets','aarch64-apple-darwin.tar.gz','ripsecrets'),('talisman','thoughtworks/talisman','talisman_darwin_arm64','talisman'),('trivy','aquasecurity/trivy','macOS-ARM64.tar.gz','trivy'),('leakferret','leakferrethq/leakferret','aarch64-apple-darwin.tar.gz','leakferret'),('noseyparker','praetorian-inc/noseyparker','aarch64-apple-darwin.tar.gz','noseyparker'),('rusty-hog','newrelic/rusty-hog','darwin-duroc_hog-1.0.11.zip','duroc_hog')]
def f(s):
 id,repo,ending,exe=s
 try:
  d=json.load(urllib.request.urlopen('https://api.github.com/repos/'+repo+'/releases/latest'))
  a=next(a for a in d['assets'] if a['name'].endswith(ending))
  out=root/'source'/id;out.mkdir(exist_ok=True)
  archive=out/a['name'];urllib.request.urlretrieve(a['browser_download_url'],archive)
  sha=hashlib.sha256(archive.read_bytes()).hexdigest()
  if tarfile.is_tarfile(archive):
   with tarfile.open(archive) as t:t.extractall(out,filter='data')
   binary=next(p for p in out.rglob(exe) if p.is_file())
  elif zipfile.is_zipfile(archive):
   with zipfile.ZipFile(archive) as z:z.extractall(out)
   binary=next(p for p in out.rglob(exe) if p.is_file())
  else:binary=archive
  binary.chmod(0o755); dest=root/'binaries'/exe
  if dest.exists() or dest.is_symlink():dest.unlink()
  dest.symlink_to(binary)
  return dict(id=id,status='installed_unverified',version=d['tag_name'],source_url='https://github.com/'+repo,asset_url=a['browser_download_url'],commit_or_digest='sha256:'+sha,executable=str(dest),install_command='python3 bench/tools/install_releases.py',commands={},parser=id.replace('-','_'),accepted_exit_codes=[0,1],offline=True)
 except Exception as e:return dict(id=id,status='install_failed',reason=str(e),source_url='https://github.com/'+repo,commands={})
rows=list(concurrent.futures.ThreadPoolExecutor(4).map(f,specs))
(root/'manifest.json').write_text(json.dumps({'schema_version':1,'tools':rows},indent=2)+'\n')
for r in rows:print(r['id'],r['status'],r.get('version'),r.get('reason',''))
