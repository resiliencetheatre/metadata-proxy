#!/usr/bin/env python3
"""Repeatable loopback baseline. No unsigned mode in metadata-proxy itself."""
import argparse,csv,json,os,pathlib,platform,signal,socket,subprocess,tempfile,time
ROOT=pathlib.Path(__file__).resolve().parents[1]
PROXY=str(ROOT/'metadata-proxy'); TRAFFIC=str(ROOT/'tools/udp-traffic')
p=argparse.ArgumentParser()
p.add_argument('--seconds',type=float,default=30)
p.add_argument('--repeats',type=int,default=3)
p.add_argument('--rates',default='50,1000,10000,0',help='0 is saturation')
p.add_argument('--sizes',default='64,1079')
p.add_argument('--output',default='results/e2e.csv')
a=p.parse_args()
assert a.seconds>0 and a.repeats>0
sizes=list(map(int,a.sizes.split(',')));rates=list(map(int,a.rates.split(',')))
assert all(8<=z<=1079 for z in sizes) and all(r>=0 for r in rates)
def port():
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:s.bind(('127.0.0.1',0));return s.getsockname()[1]
def start(args,log):
    return subprocess.Popen(args,stdout=log,stderr=log)
def finish(proc):
    # wait4 provides per-child CPU rather than cumulative RUSAGE_CHILDREN.
    deadline=time.monotonic()+a.seconds+15
    while True:
        pid,status,usage=os.wait4(proc.pid,os.WNOHANG)
        if pid:break
        if time.monotonic()>deadline:raise TimeoutError(proc.args)
        time.sleep(.02)
    proc.returncode=os.waitstatus_to_exitcode(status)
    if proc.returncode:raise RuntimeError((proc.args,proc.returncode))
    return usage.ru_utime,usage.ru_stime
out=pathlib.Path(a.output);out.parent.mkdir(parents=True,exist_ok=True)
# Probe before starting any children; fail clearly when sandbox disallows sockets.
try:port()
except OSError as e:raise SystemExit(f'UDP measurements unavailable: {e}')
metadata={'platform':platform.platform(),'architecture':platform.machine(),'cpu':next((s.split(':',1)[1].strip() for s in pathlib.Path('/proc/cpuinfo').read_text().splitlines() if s.startswith('model name')),'unknown'),'affinity':sorted(os.sched_getaffinity(0)),'clock':'CLOCK_MONOTONIC','seconds':a.seconds,'repeats':a.repeats,'rates':rates,'sizes':sizes,'compiler':subprocess.check_output([os.environ.get('CC','cc'),'--version'],text=True).splitlines()[0],'libsodium':subprocess.check_output(['pkg-config','--modversion','libsodium'],text=True).strip(),'flags':os.environ.get('CFLAGS','Makefile default: -O2 -g -std=c11 -Wall -Wextra -Wpedantic')}
out.with_suffix('.environment.json').write_text(json.dumps(metadata,indent=2)+'\n')
with tempfile.TemporaryDirectory() as td, out.open('w') as csvfile:
    d=pathlib.Path(td)
    subprocess.run([PROXY,'keygen','--secret',str(d/'seed'),'--public',str(d/'pk')],check=True)
    (d/'trust').write_text((d/'pk').read_text().strip()+' HOST-A\n')
    fields=['path','payload_bytes','rate','repeat','duration','sent','received','lost','duplicates','reordered','invalid','send_errors','offered_pps','goodput_bps','wrapper_inclusive_bps','generator_user_s','generator_system_s','sink_user_s','sink_system_s','relays_user_s','relays_system_s','total_cpu_percent','rcvbuf','sndbuf']
    writer=csv.DictWriter(csvfile,fieldnames=fields);writer.writeheader()
    for mode in ['direct','plain-relay-benchmark-only','signed']:
      for size in sizes:
       for rate in rates:
        for repeat in range(1,a.repeats+1):
          procs=[];logs=[]
          try:
            sink_port,first,second=port(),port(),port()
            while len({sink_port,first,second})<3:sink_port,first,second=port(),port(),port()
            def launch(args,name):
                f=(d/name).open('w+');logs.append(f);proc=start(args,f);procs.append(proc);return proc,f
            sink,sinklog=launch([TRAFFIC,'sink',str(sink_port),str(a.seconds+10),str(size)],'sink')
            relays=[]
            if mode=='plain-relay-benchmark-only':
                for i,(src,dst) in enumerate([(first,second),(second,sink_port)]):
                    proc,log=launch([TRAFFIC,'relay',str(src),str(dst),str(a.seconds+10)],f'relay{i}');relays.append((proc,log))
            elif mode=='signed':
                proc,log=launch([PROXY,'decap','--listen',f'127.0.0.1:{second}','--forward',f'127.0.0.1:{sink_port}','--trust',str(d/'trust'),'--stats-interval','0'],'decap');relays.append((proc,log))
                proc,log=launch([PROXY,'encap','--listen',f'127.0.0.1:{first}','--peer',f'127.0.0.1:{second}','--label','HOST-A','--secret',str(d/'seed'),'--stats-interval','0'],'encap');relays.append((proc,log))
            time.sleep(.2)
            gen,genlog=launch([TRAFFIC,'send',str(sink_port if mode=='direct' else first),str(size),str(a.seconds),str(rate)],'generator')
            gu,gs=finish(gen)
            time.sleep(.3) # drain; not included in offered-load interval
            for proc,_ in relays:proc.send_signal(signal.SIGTERM)
            ru=rs=0
            for proc,log in relays:
                u,s=finish(proc);ru+=u;rs+=s;log.flush();log.seek(0)
                with out.with_suffix('.process.log').open('a') as raw:raw.write(f'{mode} size={size} rate={rate} repeat={repeat} command={proc.args} user_seconds={u} system_seconds={s}\n'+log.read())
            sink.send_signal(signal.SIGTERM);su,ss=finish(sink)
            def read(log):log.flush();log.seek(0);return json.loads(log.read())
            g=read(genlog);s=read(sinklog);elapsed=g['elapsed']
            row=dict(path=mode,payload_bytes=size,rate=rate,repeat=repeat,duration=elapsed,sent=g['sent'],received=s['received'],lost=g['sent']-s['received'],duplicates=s['duplicates'],reordered=s['reordered'],invalid=s['invalid'],send_errors=g['errors'],offered_pps=g['sent']/elapsed,goodput_bps=s['received']*size*8/elapsed,wrapper_inclusive_bps=s['received']*(size+(121 if mode=='signed' else 0))*8/elapsed,generator_user_s=gu,generator_system_s=gs,sink_user_s=su,sink_system_s=ss,relays_user_s=ru,relays_system_s=rs,total_cpu_percent=(gu+gs+su+ss+ru+rs)/elapsed*100,rcvbuf=s['rcvbuf'],sndbuf=g['sndbuf'])
            writer.writerow(row);csvfile.flush();print(mode,size,rate,repeat,'received',s['received'],'lost',row['lost'],flush=True)
          finally:
            for proc in procs:
                if proc.returncode is None:
                    proc.terminate()
                    try:proc.wait(timeout=3)
                    except subprocess.TimeoutExpired:proc.kill();proc.wait(timeout=3)
            for log in logs:log.close()
