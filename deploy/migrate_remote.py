import datetime, hashlib, http.client, json, os, pathlib, shutil, socket, subprocess, sys, time
stage = pathlib.Path(sys.argv[1])
backup = pathlib.Path('/var/backups/mubeng') / datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
binary = pathlib.Path('/usr/bin/mubeng')
unit = pathlib.Path('/etc/systemd/system/mubeng.service')
config = pathlib.Path('/etc/mubeng/pools.json')
def run(args, **kw): return subprocess.run(args, check=True, **kw)
def health():
    run(['systemctl','is-active','--quiet','mubeng'])
    with socket.create_connection(('127.0.0.1',3153),timeout=3): pass
    with socket.create_connection(('127.0.0.1',3154),timeout=3) as conn:
        conn.sendall(b'\x05\x01\x00')
        if conn.recv(2) != b'\x05\x00': raise RuntimeError('SOCKS5 negotiation failed')
    conn=http.client.HTTPConnection('127.0.0.1',9090,timeout=3)
    conn.request('GET','/metrics'); resp=conn.getresponse(); body=resp.read().decode(); conn.close()
    if resp.status != 200 or 'mubeng_pool_size{pool="http"}' not in body or 'mubeng_pool_size{pool="socks"}' not in body: raise RuntimeError('named pool metrics missing')
run([str(stage/'mubeng'),'--config',str(stage/'mubeng.json'),'--validate-config'], stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
run(['systemd-analyze','verify',str(stage/'mubeng.service')])
if hashlib.sha256(binary.read_bytes()).hexdigest() != (stage/'original-binary.sha256').read_text().strip(): raise RuntimeError('binary changed after inspection')
if hashlib.sha256(unit.read_bytes()).hexdigest() != (stage/'original-unit.sha256').read_text().strip(): raise RuntimeError('service changed after inspection')
backup.mkdir(parents=True, mode=0o700)
shutil.copy2(binary,backup/'mubeng'); shutil.copy2(unit,backup/'mubeng.service')
had_config=config.exists()
if had_config: shutil.copy2(config,backup/'pools.json')
manifest={'had_config':had_config,'proxy_files_sha256':{str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in [pathlib.Path('/etc/default/proxies'),pathlib.Path('/etc/default/proxies-socks5')]}}
(backup/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
def replace(src,dst,mode):
    dst.parent.mkdir(parents=True,exist_ok=True)
    tmp=dst.with_name(dst.name+'.multipool-new'); shutil.copyfile(src,tmp); tmp.chmod(mode); os.replace(tmp,dst)
try:
    replace(stage/'mubeng',binary,0o755)
    replace(stage/'mubeng.service',unit,0o644)
    replace(stage/'mubeng.json',config,0o644)
    run(['systemctl','daemon-reload']); run(['systemctl','restart','mubeng'])
    failure=None
    for _ in range(30):
        try: health(); break
        except Exception as exc: failure=exc; time.sleep(.5)
    else: raise RuntimeError(f'health checks failed: {failure}')
    for path,digest in manifest['proxy_files_sha256'].items():
        if hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()!=digest: raise RuntimeError('upstream file unexpectedly changed')
    print(json.dumps({'status':'healthy','backup':str(backup),'binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),'ports':[3153,3154,9090]}))
except BaseException:
    replace(backup/'mubeng',binary,0o755); replace(backup/'mubeng.service',unit,0o644)
    if had_config: replace(backup/'pools.json',config,0o644)
    else: config.unlink(missing_ok=True)
    run(['systemctl','daemon-reload']); run(['systemctl','restart','mubeng'])
    print('Migration failed; restored prior binary, service, and config.',file=sys.stderr)
    raise
