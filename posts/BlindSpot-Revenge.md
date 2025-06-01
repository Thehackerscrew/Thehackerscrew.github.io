# Summary


This challenge implements a server that performs blind signatures by interacting with a client (us). We can request as many signatures as we wish from the server, with the goal being to produce at least one more valid signature that the number of signatures we asked from the server. The server keeps count of both how many messages it has signed and how many signatures of different messages it has validated, if at any point the number of validations exceeds the number of signings, we receive the flag.

  
  

# Analysis

The typical Schnorr sigma protocol involves 3 steps:

- (P -> V) Prover sends to the verifier the commitment `R = r*G`, where r is a uniformly random number.

- (V -> P) Verifier responds with a challenge `c`.

- (P -> V) Prover calculates `s = r + c*x` where `x` is the secret key of the Prover, and sends it to the Verifier. The Verifier can then check that `s*G == R + c*Q` (`Q` is the public key of the Prover).

And this can easily be turned into a non-interactive signature scheme by applying the Fiat-Shamir transform to calculate the challenge at the 2nd step. The signature is a pair `(R, s)`

  

In the challenge setting, instead of having the 2nd step being non-interactive, we, as the client, get to select the challenge `c`. If we wanted to play "fair" we would go through the Schnorr protocol as normal, optionally applying a blinding factor, if we wished to anonymize the signing interaction and dissasociate it from the actual signature produced. 

However, the verification function still requires that the value of `c` used in verification (which can optionally be different from the `c` value sent during signing, due to the blinding) is calculated by hashing the random commitment `R` together with the signed message:

  

```python
def hash_func(Rp, m):
	if  isinstance(m, str):
	m = m.encode()
	return (
		int.from_bytes(hashlib.sha256(point2bytes(Rp) + m).digest(), byteorder="big") % p
	)
	
def Verify(Q, m, sig):
	R_prime, s_prime = sig
	c_prime = hash_func(R_prime, m)
	return gen * s_prime == R_prime + Q * c_prime
```

The references to `R_prime, s_prime, c_prime` instead of `R, s, c`  are again because of the possible blinding, that does not guarantee that original values used during signing are the same as the ones used in verification.

We would expect that due to the use of the hash, it's difficult to break this scheme, however as the authors of https://eprint.iacr.org/2020/945.pdf showed, it's possible to create forgeries by utilizing parallel connections. Instead of completing signing interactions sequentially, we can instead open many connections, acquire the commitments for each of those (only doing step 1), and carefully select what challenges to send before proceeding with step 2 of the protocol, in order to perform a forgery. TBH, I don't fully understand the attack but it involves decomposing the extra target message we want to forge a signature for into each bit representation, and depending on the value of each bit select one of two possible blind factors to apply to each `R` commitment we received. This shows that we need at least 256 parallel connections, since the elliptic curve the scheme works with has a 256-bit order. Depending on each selected blind factor, a corresponding challenge is calculated. After this decomposition, the challenges are all sent to their corresponding signing sessions, and the server responds with the `s` values. We use these to calculate an extra pair `(R, s)` for the target message we want to maliciously sign.

Thankfully, the authors of the paper have provided code for this exact setting, so instead of implementing the paper from scratch, we can simply adapt their code for the challenge. A bit of struggling with connecting with the server and we get the following solve script:

```python
from pwn import *
import json
import hashlib
from tqdm import trange
from sage.all import GF, Integer, EllipticCurve

p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
K = GF(p)
a = K(0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc)
b = K(0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b)
E = EllipticCurve(K, (a, b))
G = E(0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296, 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5)
E.set_order(0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551 * 0x1)
q = E.order()
p = q
Zp = GF(q)

def inner_product(coefficients, values):
    return sum(y*x for x, y in zip(coefficients, values))

def point2bytes(P):
    return bytes.fromhex(f"{int(P.xy()[0]):064x}{int(P.xy()[1]):064x}")

def H(R, m):
    if isinstance(m, str):
        m = m.encode()
    h = hashlib.sha256(point2bytes(R) + m).digest()
    return int.from_bytes(h, 'big') % q

global X
X = None

def get_conn():
    conn = remote("tcp.sasc.tf", 14440)
    conn.recvline()
    return conn

print("[+] Reset")
rr = get_conn()
rr.send(b"reset")
rr.close()

def sign1(conn):
    global X
    conn.send(b"sign")
    res = json.loads(conn.recvline().decode().strip())
    R = E(res["R"])
    Q = E(res["Q"])
    if X == None:
        X = Q
    else:
        assert Q == X
    return R

def sign2(conn, c):
    conn.sendline(json.dumps({"c": c}).encode())
    res = json.loads(conn.recvline().decode().strip())
    s = res['s']
    return Zp(int(s))

random_oracle = H

ell = 256
conns = [get_conn() for _ in trange(ell)]
messages = [f"message_{i}" for i in range(ell)] + ["forged message"]
Rs = [sign1(conn) for conn in conns]

alpha = [[Zp.random_element(), Zp.random_element()] for i in range(ell)]
beta = [Zp.random_element() for i in range(ell)] # if we implemented this from scratch we could simply set all betas to 0/remove them from the rest of the script for simplicity
blinded_R = [[Rs[i] + G * alpha[i][b] + X * beta[i] for b in range(2)] for i in range(ell)]

c = [[H(blinded_R[i][b], messages[i]) for b in range(2)] for i in range(ell)]

P = ([-sum([Zp(2)**i * c[i][0]/(c[i][1] - c[i][0]) for i in range(ell)])] + [Zp(2)**i / (c[i][1] - c[i][0]) for i in range(ell)])
c_to_decompose = random_oracle(inner_product(P[1:], Rs), messages[ell])
bits = [int(b) for b in bin(c_to_decompose - inner_product(P[1:], beta) + P[0]) [2:].rjust(256, '0')][::-1]
blinded_c = [c[i][b] + beta[i] for (i, b) in enumerate(bits)]

# next step is to get server response
print("[+] Sign part 2")
s = [sign2(conn, int(cc)) for conn, cc in zip(conns, blinded_c)]
forged_signatures = [(blinded_R[i][bits[i]], s[i] + alpha[i][bits[i]]) for i in range(ell)]


forged_signatures += [(inner_product(P[1:], Rs), inner_product(P[1:], s))] # one extra
print(forged_signatures[:3])


def verify(conn, sig, msg):
    conn.send(b"verify")
    R, s = sig
    Rx, Ry = [int(ii) for ii in R.xy()[:2]]
    sig = ([Rx, Ry], int(s))
    conn.send(json.dumps({"msg": msg, "sig": sig}).encode())
    print(conn.recvline())


for msg, fsig in zip(messages, forged_signatures):
    new_conn = get_conn()
    verify(new_conn, fsig, msg)
    
new_conn.interactive()

# SAS{3ven_7h3_4uth0r_of_bl1nd5p07_t4sk_h45_bl1nd5pot}
```