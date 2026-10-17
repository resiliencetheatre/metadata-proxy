#!/usr/bin/env python3
"""Bounded subprocess/socket integration tests; no Python dependency in production."""
import os, pathlib, socket, subprocess, tempfile, time, signal, struct, hashlib
ROOT = pathlib.Path(__file__).resolve().parents[1]
BIN = str(ROOT / 'metadata-proxy')


def command(*args, ok=True):
    p = subprocess.run([BIN, *map(str,args)], capture_output=True, timeout=10)
    assert (p.returncode == 0) == ok, (args,p.returncode,p.stderr,p.stdout)
    return p

def bound(family):
    s=socket.socket(family,socket.SOCK_DGRAM)
    s.bind(('::1' if family==socket.AF_INET6 else '127.0.0.1',0))
    s.settimeout(.25)
    return s

def endpoint(s):
    h,p=s.getsockname()[:2]
    return f'[{h}]:{p}' if ':' in h else f'{h}:{p}'

def absent(s):
    try: data=s.recv(65535)
    except socket.timeout: return
    raise AssertionError(('unexpected output',data))

with tempfile.TemporaryDirectory() as td:
    d=pathlib.Path(td); secret=d/'seed'; public=d/'public'; trust=d/'trust'
    command('keygen','--secret',secret,'--public',public)
    assert secret.stat().st_mode & 0o777 == 0o600
    assert len(secret.read_bytes())==65 and len(public.read_bytes())==65
    old=secret.read_bytes();command('keygen','--secret',secret,'--public',public,ok=False);assert secret.read_bytes()==old
    trust.write_text('# comment\n\n'+public.read_text().strip()+' HOST-A\n'+public.read_text().strip()+' '+'A'*63+'\n')
    command('--help');command('encap','--help');command('bogus',ok=False)
    command('encap','--listen','::1:5000','--peer','127.0.0.1:6000','--label','HOST-A','--secret',secret,ok=False)
    for data in [b'',b'0'*64,b'0'*64+b'\nX',b'G'*64+b'\n',b'0'*63+b'\n']:
        (d/'badseed').write_bytes(data)
        command('encap','--listen','127.0.0.1:5000','--peer','127.0.0.1:6000','--label','HOST-A','--secret',d/'badseed',ok=False)
    for data in ['bad HOST-A\n',public.read_text().strip()+' bad/label\n',public.read_text().strip()+' HOST-A extra\n','x'*1000,public.read_text().strip()+' HOST-A\0hidden\n']:
        (d/'badtrust').write_text(data)
        bad=command('decap','--listen','127.0.0.1:5000','--forward','127.0.0.1:6000','--trust',d/'badtrust',ok=False)
        assert b'invalid trust file' in bad.stderr
    # Inspect the fixed fixture even where socket operations are prohibited.
    fixture=bytes.fromhex((ROOT/'tests/fixture.hex').read_text())
    (d/'fixture').write_bytes(fixture)
    (d/'fixturetrust').write_text('03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8 HOST-A\n')
    inspected=command('inspect','--packet',d/'fixture','--trust',d/'fixturetrust')
    assert b'signature_validity=true' in inspected.stdout
    assert b'replay_protection=none' in inspected.stdout
    (d/'fixturetrust').write_text('03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8 OTHER\n')
    inspected=command('inspect','--packet',d/'fixture','--trust',d/'fixturetrust',ok=False)
    assert b'authorized_label=false' in inspected.stdout and b'signature_validity=true' in inspected.stdout
    (d/'fixture').write_bytes(fixture+b'x')
    command('inspect','--packet',d/'fixture','--trust',d/'fixturetrust',ok=False)
    for family in [socket.AF_INET,socket.AF_INET6]:
        children=[];sockets=[]
        try:
            try: sink=bound(family)
            except OSError as e:
                if isinstance(e,PermissionError): print('SKIP UDP integration: socket creation prohibited:',e);continue
                if family==socket.AF_INET6: print('SKIP IPv6:',e);continue
                raise
            sockets.append(sink)
            capture=bound(family);sockets.append(capture)
            encport=bound(family);encaddr=encport.getsockname();encendpoint=endpoint(encport);encport.close()
            decport=bound(family);decaddr=decport.getsockname();decendpoint=endpoint(decport);decport.close()
            def launch(*args):
                p=subprocess.Popen([BIN,*map(str,args)],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
                children.append(p);return p
            enc=launch('encap','--listen',encendpoint,'--peer',endpoint(capture),'--label','HOST-A','--secret',secret,'--stats-interval','0')
            dec=launch('decap','--listen',decendpoint,'--forward',endpoint(sink),'--trust',trust,'--stats-interval','0','--max-sessions','2')
            time.sleep(.15);assert enc.poll() is None and dec.poll() is None
            sender=socket.socket(family,socket.SOCK_DGRAM);sockets.append(sender)
            packets=[]
            for payload in [b'',b'\0a\0b',b'\x80\x60'+bytes(range(158)),os.urandom(512),os.urandom(1079)]:
                sender.sendto(payload,encaddr);wire=capture.recv(65535);assert len(wire)==len(payload)+121
                sender.sendto(wire,decaddr);assert sink.recv(65535)==payload;absent(sink);packets.append(wire)
            sender.sendto(b'x'*1080,encaddr);absent(capture)
            sender.sendto(b'x'*2000,encaddr);absent(capture)
            sender.sendto(packets[-1],decaddr);absent(sink)
            wire=packets[2]
            # Each field, signature, payload, truncation, trailing data.
            for offset in [0,4,5,6,8,9,11,19,27,43,51,57,121]:
                bad=bytearray(wire);bad[offset]^=128;sender.sendto(bad,decaddr)
            for end in range(len(wire)): sender.sendto(wire[:end],decaddr)
            sender.sendto(wire+b'x',decaddr);sender.sendto(b'x'*2000,decaddr);absent(sink)
            for i in range(3):
                sender.sendto(bytes([i]),encaddr);packets.append(capture.recv(65535))
            for i in [-1,-3,-2]: sender.sendto(packets[i],decaddr);assert sink.recv(65535)==bytes([i+3 if i==-3 else 2 if i==-1 else 1])
            # Independent signatures permit testing authenticated unauthorized, stale/future and session caps.
            try:
                from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
                key=Ed25519PrivateKey.from_private_bytes(bytes.fromhex(secret.read_text().strip()))
                def signed(label='HOST-A',ts=None,sid=b'S'*16,seq=0):
                    if ts is None: ts=int(time.time()*1000)
                    l=label.encode();payload=b'valid'
                    head=b'MDPX'+bytes([1,0])+struct.pack('>HBH',115+len(l),len(l),len(payload))+hashlib.sha256(bytes.fromhex(public.read_text().strip())).digest()[:8]+struct.pack('>Q',ts)+sid+struct.pack('>Q',seq)+l
                    return head+key.sign(b'metadata-proxy/v1'+head+payload)+payload
                for wire in [signed(label='HOST-B'),signed(ts=0),signed(ts=2**64-1)]:sender.sendto(wire,decaddr);absent(sink)
                sender.sendto(signed(),decaddr);assert sink.recv(65535)==b'valid'
                sender.sendto(signed(sid=b'T'*16),decaddr);absent(sink)
                # Offline inspect authenticates but intentionally ignores age/replay.
                (d/'packet').write_bytes(signed(ts=0));p=command('inspect','--packet',d/'packet','--trust',trust);assert b'signature_validity=true' in p.stdout
                (d/'packet').write_bytes(signed(label='HOST-B'));command('inspect','--packet',d/'packet','--trust',trust,ok=False)
                # Fixture cross-check, independent OpenSSL-backed binding.
                seed=bytes(range(32));fixture=bytes.fromhex((ROOT/'tests/fixture.hex').read_text())
                Ed25519PrivateKey.from_private_bytes(seed).public_key().verify(fixture[57:121],b'metadata-proxy/v1'+fixture[:57]+fixture[121:])
            except ImportError: print('SKIP independent binding and authenticated edge integration: cryptography unavailable')
            dec.send_signal(signal.SIGTERM);_,err=dec.communicate(timeout=3);assert dec.returncode==0 and b'replay_drops=' in err
            dec=launch('decap','--listen',decendpoint,'--forward',endpoint(sink),'--trust',trust,'--stats-interval','0')
            time.sleep(.1);sender.sendto(packets[0],decaddr);assert sink.recv(65535)==b''
            print(('IPv6' if family==socket.AF_INET6 else 'IPv4')+': preservation, empty/boundary, reordering, rejection, restart passed')
        finally:
            for p in children:
                if p.poll() is None:p.terminate()
                try:_,err=p.communicate(timeout=3)
                except subprocess.TimeoutExpired:p.kill();_,err=p.communicate(timeout=3);raise
                assert p.returncode==0,(p.returncode,err)
            for s in sockets:s.close()
print('configuration checks passed; UDP test/skip results reported above')
