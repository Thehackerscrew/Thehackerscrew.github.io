# Solve Script

```python
import numpy as np
from sage.all import *

#Load the encrypted message
msg=bytes.fromhex('33b4ba0c3c11ad7e298b79de7261c5dd8edd7b537007b383cad9f38dbcf584e66a07c9808edad6e289516f3c6cc4186686f3a7fc8e1603e80aba601efe82e8cf2f6a28aa405cf7419b9dd1f01925c5')


#Load the pubkey
G_pub = np.load('alice_pub.npy')

print("Public key shape:", G_pub.shape)

import itertools

def hex_to_bits(c_hex, total_bits):
    c_int = int(c_hex, 16)
    bin_str = bin(c_int)[2:].rjust(total_bits, '0')
    return [int(b) for b in bin_str]

def split_bits(bits, k):
    return [bits[i:i+k] for i in range(0, len(bits), k)]

#break message in blocks of 63 bits. Code is 57x63 matrix
c_hex = msg.hex()
total_bits = 630
K=63
c_bits = hex_to_bits(c_hex, total_bits)
c_bits_blocks = split_bits(c_bits, K)



G = Matrix(GF(2), G_pub.tolist())


msg=[]

for a in c_bits_blocks:
  #Only one error, this means that we can decode by just bruteforcing it
  r=vector(GF(2),a)
  W=False
  for i in range(63):
    R=list(r)
    R[i]+=1
    R=vector(GF(2),R)
    #  print(R)
    try:
      D=G.solve_left(R)
      print(D)
      msg+=list(D)
      #  print(len(D),W)
      if W:
        assert(False)
      W=True
    except:
      None
  #  exit(0)

#join the message again and transform into bytes to get flag
msg="".join([str(a) for a in msg])

msg=[int(msg[i:i+8],2) for i in range(0,len(msg)-2,8)]
print(msg)
print(bytes(msg))
#SAS{y0u_d0nt_r3ally_n33d_S_perm_t0_d3c0d3_Mc_3l1ec3_w1th_H4mm1ng_c0d3s}
```
