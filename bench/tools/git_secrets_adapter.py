#!/usr/bin/env python3
"""Official AWS rules, isolated config, no local credential-provider access."""
import pathlib,subprocess,sys,tempfile,os
exe=str(pathlib.Path(__file__).resolve().parent/'source/git-secrets/git-secrets')
mode,path=sys.argv[1:3]
with tempfile.TemporaryDirectory(prefix='gs-benchmark-') as tmp:
 env=os.environ.copy();env.update(HOME=tmp,GIT_CONFIG_NOSYSTEM='1',GIT_CONFIG_GLOBAL='/dev/null')
 subprocess.run(['git','init','-q',tmp],env=env,check=True)
 subprocess.run([exe,'--register-aws'],cwd=tmp,env=env,check=True,stdout=subprocess.DEVNULL)
 subprocess.run(['git','config','--unset-all','secrets.providers'],cwd=tmp,env=env,check=True)
 env['GIT_CONFIG_GLOBAL']=tmp+'/.git/config'
 cwd=tmp if mode=='fs' else path
 args=['--scan','-r',path] if mode=='fs' else ['--scan-history'] if mode=='git' else ['--scan','--cached']
 r=subprocess.run([exe]+args,cwd=cwd,env=env,capture_output=True)
 sys.stdout.buffer.write(r.stderr);sys.stderr.buffer.write(r.stdout);sys.exit(r.returncode)
