#!/usr/bin/env python3
"""Run scan and report in a fresh datastore; propagate failures."""
import pathlib,subprocess,sys,tempfile
exe=str(pathlib.Path(__file__).resolve().parent/'binaries/noseyparker')
with tempfile.TemporaryDirectory(prefix='np-benchmark-') as tmp:
 datastore=tmp+'/datastore'
 r=subprocess.run([exe,'scan','--datastore',datastore,'--git-history','none' if sys.argv[1]=='fs' else 'full','--quiet',sys.argv[2]],stdout=subprocess.DEVNULL)
 if r.returncode:sys.exit(r.returncode)
 sys.exit(subprocess.run([exe,'report','--datastore',datastore,'--format','sarif','--output',sys.argv[3],'--quiet']).returncode)
