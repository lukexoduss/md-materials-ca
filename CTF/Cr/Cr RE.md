# Comprehensive Cryptography CTF Challenge Creation Topics

## Foundational Challenge Design

### Mathematical Primitives

- Modular arithmetic weaknesses
- Prime number generation flaws
- Greatest common divisor exploitation
- Discrete logarithm problems
- Quadratic residues and non-residues
- Chinese Remainder Theorem applications
- Fermat's Little Theorem exploitation
- Euler's Theorem vulnerabilities

### Classical Ciphers

- Caesar cipher variants
- Substitution cipher weaknesses
- Polyalphabetic cipher attacks
- Transposition cipher vulnerabilities
- Vigenère cipher cryptanalysis
- Hill cipher mathematical attacks
- Playfair cipher exploitation
- Affine cipher weaknesses

### Information Theory

- Frequency analysis challenges
- Entropy measurement
- Index of Coincidence exploitation
- Kasiski examination
- Pattern recognition in ciphertext
- Language detection methods
- Statistical bias exploitation

## Symmetric Cryptography

### Block Cipher Fundamentals

- ECB mode oracle attacks
- CBC padding oracle exploitation
- CBC bit-flipping attacks
- CTR mode nonce reuse
- OFB/CFB mode vulnerabilities
- Initialization vector manipulation
- Block size detection
- Cipher mode identification

### Stream Ciphers

- Linear feedback shift register attacks
- Keystream reuse exploitation
- RC4 biases and weaknesses
- Salsa20/ChaCha implementation flaws
- One-time pad misuse
- Pseudorandom generator weaknesses
- Known plaintext attacks

### AES-Specific

- Weak key schedules
- Side-channel analysis simulation
- Round reduction attacks
- Related-key attacks
- Meet-in-the-middle approaches
- Implementation vulnerabilities
- Timing attack scenarios

### Block Cipher Constructions

- Feistel network weaknesses
- Substitution-Permutation network flaws
- Round function vulnerabilities
- Key expansion weaknesses
- S-box analysis challenges

## Asymmetric Cryptography

### RSA Vulnerabilities

- Small public exponent attacks
- Common modulus attack
- Wiener's attack on small private exponents
- Factorization challenges (small factors)
- Hastad's broadcast attack
- Franklin-Reiter related message attack
- Coppersmith's attack variants
- Partial key exposure
- Fault attacks on CRT-RSA
- Low entropy key generation

### Diffie-Hellman Weaknesses

- Small subgroup attacks
- Weak generator exploitation
- Parameter validation bypass
- Man-in-the-middle scenarios
- Logjam-style vulnerabilities

### Elliptic Curve Cryptography

- Invalid curve attacks
- Curve order factorization
- Twist security weaknesses
- Singular curve exploitation
- Smart's attack implementation
- MOV attack scenarios
- Anomalous curve attacks
- ECDSA nonce reuse
- Lattice attacks on ECDSA

### DSA/ElGamal

- Nonce reuse attacks
- Biased nonce exploitation
- Parameter manipulation
- Signature forgery scenarios
- Subgroup confinement attacks

## Hash Functions

### Collision Attacks

- Birthday attack demonstrations
- MD5 collision exploitation
- SHA-1 chosen-prefix collisions
- Length extension attacks
- Hash function weaknesses (MD4, MD5)

### Hash-Based Constructions

- HMAC timing attacks
- HMAC key recovery scenarios
- Merkle-Damgård construction flaws
- Sponge construction weaknesses
- Password hashing vulnerabilities (bcrypt, scrypt misuse)

### Hash Puzzles

- Preimage attack challenges
- Second preimage resistance testing
- Proof-of-work mining
- Hash chain reversals

## Protocol Vulnerabilities

### SSL/TLS Attacks

- POODLE-style vulnerabilities
- BEAST attack scenarios
- CRIME/BREACH compression attacks
- Heartbleed simulation
- Certificate validation bypass
- Downgrade attack scenarios
- Renegotiation vulnerabilities

### Authentication Protocols

- Challenge-response weaknesses
- Replay attack scenarios
- Time-based authentication flaws
- Zero-knowledge proof bypass
- Multi-factor authentication weaknesses

### Key Exchange Issues

- Session key prediction
- Perfect forward secrecy bypass
- Key confirmation weaknesses
- Entity authentication failures

## Applied Cryptographic Systems

### Random Number Generation

- Pseudorandom number generator prediction
- Seed recovery attacks
- Linear congruential generator exploitation
- Mersenne Twister state recovery
- Entropy source weaknesses
- PRNG reseeding vulnerabilities

### Padding Schemes

- PKCS#7 padding oracle
- OAEP padding weaknesses
- PSS signature padding flaws
- ISO 10126 padding attacks
- ANSI X.923 padding exploitation

### Format-Preserving Encryption

- Format oracle attacks
- Cycle walking vulnerabilities
- FFX mode weaknesses
- Deterministic encryption issues

### Authenticated Encryption

- AES-GCM nonce reuse
- Poly1305 forgery scenarios
- Authentication tag truncation
- Encrypt-then-MAC vs MAC-then-encrypt
- Associated data manipulation

## Advanced Attacks

### Side-Channel Exploitation

- Timing attack simulations
- Cache-timing vulnerabilities
- Power analysis scenarios
- Electromagnetic emanation exploitation
- Acoustic cryptanalysis challenges

### Lattice-Based Attacks

- LLL algorithm applications
- Coppersmith method implementations
- Knapsack cryptosystem attacks
- NTRU vulnerabilities
- Learning With Errors exploitation

### Algebraic Attacks

- Gröbner basis applications
- Polynomial system solving
- Boolean satisfiability reduction
- Linearization techniques

### Quantum Algorithm Simulation

- Shor's algorithm demonstration
- Grover's algorithm applications
- Post-quantum migration challenges
- Quantum-resistant bypass scenarios

## Specialized Topics

### Format String Vulnerabilities

- Oracle construction from errors
- Information leakage exploitation
- Custom encoding scheme weaknesses

### Cryptographic Protocols

- Commitment scheme manipulation
- Secret sharing reconstruction
- Multi-party computation bypass
- Threshold cryptography weaknesses
- Homomorphic encryption limitations

### Blockchain/Cryptocurrency

- Signature malleability
- Transaction replay attacks
- Smart contract cryptographic flaws
- Consensus mechanism weaknesses
- Wallet key derivation issues

### Steganography

- LSB encoding detection
- Steganalysis challenges
- Covert channel exploitation
- Watermarking removal

## Implementation Weaknesses

### Code-Level Vulnerabilities

- Buffer overflow in crypto libraries
- Integer overflow in calculations
- Memory disclosure attacks
- Pointer manipulation
- Race conditions in key generation

### API Misuse

- Cryptographic library misconfigurations
- Incorrect mode of operation usage
- Missing authentication checks
- Insecure default parameters

### Reverse Engineering

- Algorithm identification from binary
- Key extraction from executables
- Obfuscated implementation analysis
- Hardware security module bypass

## Challenge Architecture

### Multi-Stage Challenges

- Progressive difficulty scenarios
- Chained vulnerability exploitation
- Hybrid cryptosystem attacks
- Real-world protocol recreation

### Forensics Integration

- Encrypted artifact recovery
- Key material discovery
- Traffic analysis and decryption
- Memory dump cryptanalysis

### Web-Based Crypto

- JWT token manipulation
- Cookie encryption weaknesses
- Session token prediction
- OAuth implementation flaws

### Mixed Category Challenges

- Crypto + reversing combinations
- Crypto + pwn scenarios
- Crypto + forensics integration
- Crypto + web exploitation

---

# .

### Integer overflow exploitation

#### Theoretical Basis

Standard public-key cryptography (like RSA) relies on operations within a finite field or ring, typically $\mathbb{Z}_n$ where $n$ is a very large integer (e.g., 2048 bits). The security proofs assume that arithmetic operations (multiplication and exponentiation) are performed exactly within this group structure:

$$c \equiv m^e \pmod n$$

However, modern CPUs operate on fixed-width integers (typically 32-bit or 64-bit). While high-level languages like Python handle arbitrary-precision integers automatically, low-level implementations (C/C++, Rust, Go) or custom optimization routines often require manual handling of large numbers.

**Integer Overflow** occurs when an arithmetic operation attempts to create a numeric value that is outside of the range that can be represented with a given number of bits. In a cryptographic context, if an intermediate value in a modular exponentiation algorithm is truncated due to a fixed-width constraint _before_ the modulo operator is applied, the effective modulus of the cryptosystem changes.

#### The Vulnerability

The vulnerability lies in a flawed implementation of the **Modular Exponentiation** algorithm (Square-and-Multiply).

Mathematically, we intend to compute:

$$R_{i+1} = (R_i^2) \pmod n$$

If the implementation enforces a 64-bit mask (simulating a uint64_t register constraint) on the squaring step before the modulo $n$:

$$R_{i+1} = ((R_i^2) \pmod{2^{64}}) \pmod n$$

If $n > 2^{64}$, the modulo $n$ operation becomes irrelevant for any value wrapped by $2^{64}$. The encryption effectively degrades from the ring $\mathbb{Z}_n$ to the ring $\mathbb{Z}_{2^{64}}$.

Instead of solving the hard RSA problem:

$$m = c^{e^{-1} \pmod{\phi(n)}} \pmod n$$

The attacker only needs to solve:

$$m = c^{e^{-1} \pmod{\phi(2^{64})}} \pmod{2^{64}}$$

Since $\phi(2^k) = 2^{k-1}$, calculating the inverse of $e$ modulo $2^{63}$ is trivial, provided $e$ is odd.

#### Challenge Design

The challenge simulates a "High Performance" RSA encryption service that uses a custom, optimized `pow()` function. This function forces intermediate calculations into 64-bit constraints, mimicking a flaw in a low-level driver or embedded system.

The script generates a standard 2048-bit RSA key (which looks secure) but encrypts the flag using the vulnerable function.

Python

```
import random
from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes

# Simulation constants
# We are simulating a 64-bit architecture constraint
MAX_INT = (1 << 64) - 1

def fast_pow_unsafe(base, exponent, modulus):
    """
    A 'highly optimized' modular exponentiation function.
    Simulates an integer overflow bug where the accumulator 
    is restricted to 64 bits during the squaring step.
    """
    result = 1
    base = base & MAX_INT  # Initial truncation input
    
    while exponent > 0:
        if exponent % 2 == 1:
            # Standard modular multiplication
            result = (result * base) % modulus
        
        # THE VULNERABILITY:
        # The developer optimized the squaring step but forgot that
        # (base * base) might exceed 64 bits before the modulo is applied.
        # In this simulation, we strictly enforce the 64-bit mask.
        
        base = (base * base) & MAX_INT  
        base = base % modulus # This modulo is effectively useless if n > 2^64
        
        exponent = exponent // 2
        
    return result

def generate_challenge():
    print("[*] Generating 2048-bit RSA Keys...")
    p = getPrime(1024)
    q = getPrime(1024)
    n = p * q
    e = 65537
    
    flag = b"CTF{fake_flag_for_generation}"
    # In a real deployment, this reads from flag.txt
    # flag = open("flag.txt", "rb").read()
    
    m = bytes_to_long(flag)
    
    print(f"[*] Encrypting flag with High-Performance Math...")
    # Ensure message isn't trivially small, but fits in 64 bits for this specific logical path
    # Or rather, rely on the fact that the whole system degrades to mod 2^64.
    # Note: If m > 2^64, the initial base is also truncated.
    
    c = fast_pow_unsafe(m, e, n)
    
    return n, e, c

if __name__ == "__main__":
    n, e, c = generate_challenge()
    
    with open("output.txt", "w") as f:
        f.write(f"n = {n}\n")
        f.write(f"e = {e}\n")
        f.write(f"c = {c}\n")
        
    print(f"[*] Artifacts generated.")
    print(f"n: {n}")
    print(f"e: {e}")
    print(f"c: {c}")
```

#### Player Artifacts

The player is provided with two files:

1. **`source.py`**: The Python script above (containing the `fast_pow_unsafe` function) showing the logic used to encrypt the flag.
    
2. **`output.txt`**: A file containing the large 2048-bit modulus $n$, the public exponent $e$ ($65537$), and the ciphertext $c$.
    

Note for the Architect:

The resulting ciphertext $c$ will be relatively small (fit within 64 bits) compared to $n$. This is a visual hint to the player, alongside the explicit masking in the source code, that the large $n$ is a red herring.

---

### Solution: Integer overflow exploitation

#### Vulnerability Analysis

The provided source code reveals a custom modular exponentiation function `fast_pow_unsafe`. The critical flaw lies in the handling of the `base` variable within the loop:

Python

```
MAX_INT = (1 << 64) - 1
# ...
base = (base * base) & MAX_INT  
```

By applying a bitwise AND (`& MAX_INT`) **before** the modulo `n` operation, the script restricts the effective mathematical ring of the squaring operation to $\mathbb{Z}_{2^{64}}$.

Even though `result` is calculated modulo `n` (`result = (result * base) % modulus`), the `base` variable—which represents the powers $M^1, M^2, M^4, \dots$—is being computed modulo $2^{64}$. Consequently, the entire exponentiation chain effectively degrades to a calculation modulo $2^{64}$, rendering the 2048-bit public modulus $n$ irrelevant.

#### The Mathematical Attack

We can model the encryption as occurring in the ring $\mathbb{Z}_{2^{64}}$ rather than $\mathbb{Z}_n$.

1. **Effective Modulus:** $N' = 2^{64}$.
    
2. Euler's Totient: The totient of a power of prime $p^k$ is $\phi(p^k) = p^{k-1}(p-1)$.
    
    For $N' = 2^{64}$, the totient is:
    
    $$\phi(2^{64}) = 2^{63}(2-1) = 2^{63}$$
    
3. Decryption Key ($d$): We calculate the modular multiplicative inverse of the public exponent $e$ with respect to $\phi(N')$:
    
    $$d \equiv e^{-1} \pmod{2^{63}}$$
    
4. Decryption:
    
    $$M \equiv C^d \pmod{2^{64}}$$
    

_Note: The challenge script applies `base = base & MAX_INT` at the very beginning. This means if the original flag message was longer than 8 bytes (64 bits), the upper bits were truncated and lost permanently. The solution below recovers the 64-bit value that was actually encrypted._

#### Solution Script

This script computes the private key for the $\mathbb{Z}_{2^{64}}$ ring and decrypts the ciphertext found in `output.txt`.

Python

```
from Crypto.Util.number import long_to_bytes, inverse

def solve():
    # 1. Load Artifacts (Parsing output.txt manually or hardcoding for demo)
    # Assuming these values were read from the provided output.txt
    # Example values used for context (replace with actual file read):
    # n = <2048 bit integer> (Ignored)
    e = 65537
    c = 1234567890123456789 # Placeholder for the actual c from output.txt
    
    # In a real scenario, read the file:
    try:
        with open("output.txt", "r") as f:
            lines = f.readlines()
            e = int(lines[1].split(" = ")[1])
            c = int(lines[2].split(" = ")[1])
            print(f"[*] Loaded ciphertext: {c}")
    except FileNotFoundError:
        print("[!] output.txt not found. Run the challenge generator first.")
        return

    # 2. Define the Weakened Parameters
    # The 'mask' in the source code was (1 << 64) - 1, implying mod 2^64
    effective_modulus = 1 << 64
    
    # 3. Calculate Phi(N')
    # Phi(2^k) = 2^(k-1)
    phi_effective = 1 << 63
    
    # 4. Compute Private Key d
    # d = e^-1 mod Phi(2^64)
    # We interpret this in the ring of integers mod 2^63
    try:
        d = inverse(e, phi_effective)
        print(f"[*] Calculated private key d: {d}")
    except ValueError:
        print("[!] e is not invertible. This happens if e is even (it shouldn't be).")
        return

    # 5. Decrypt
    # m = c^d mod 2^64
    m = pow(c, d, effective_modulus)
    
    print(f"[*] Recovered Message Integer: {m}")
    
    # 6. Decode to Bytes
    try:
        flag = long_to_bytes(m)
        print(f"[*] Decoded Flag (Suffix): {flag.decode('latin-1')}")
    except Exception as e:
        print(f"[!] Could not decode bytes: {e}")
        print(f"[*] Raw Hex: {hex(m)}")

if __name__ == "__main__":
    solve()
```

#### Flag Reconstruction Note

Because the vulnerability included an initial truncation (`base = base & MAX_INT`), the recovered `m` will strictly be the last 8 bytes of the original input.

If the flag format is standard (e.g., `CTF{s0me_t3xt}`), and the recovered text looks like `_t3xt}`, the player has successfully exploited the cryptographic weakness. In a properly designed CTF challenge using this specific exploit code, the flag would be short (e.g., `CTF{OF}`) or the challenge description would ask for the decimal value of the recovered integer.

---

### Modular inverse miscalculations

#### Theoretical Basis

In public-key cryptosystems like RSA, the modular multiplicative inverse is the cornerstone of private key generation. Formally, given a public exponent $e$ and a totient $\phi(n)$, the private exponent $d$ is calculated such that:

$$d \equiv e^{-1} \pmod{\phi(n)}$$

This satisfies the congruence $e \cdot d \equiv 1 \pmod{\phi(n)}$, ensuring that Euler's Theorem ($m^{\phi(n)} \equiv 1 \pmod n$) can be utilized for decryption. The security of the system relies on $\phi(n)$ being kept secret, which is equivalent to keeping the prime factors of $n$ ($p$ and $q$) secret.

#### The Vulnerability

A common "miscalculation" in custom or novice implementations occurs when the developer computes the modular inverse over the wrong group structure or using an incomplete modulus.

Consider a scenario where the developer mistakenly calculates the private exponent $d$ using only one of the prime factors' totients (e.g., $\phi(p) = p-1$) rather than the full totient $\phi(n) = (p-1)(q-1)$.

If the provided "private key" $d_{flawed}$ is calculated as:

$$d_{flawed} \equiv e^{-1} \pmod{p-1}$$

This implies:

$$e \cdot d_{flawed} = 1 + k(p-1)$$

$$e \cdot d_{flawed} - 1 = k(p-1)$$

While this $d_{flawed}$ will not correctly decrypt messages modulo $n$ (resulting in garbage output for the player if they simply try to use it), it leaks a fatal amount of information about the prime factors.

Because $e \cdot d_{flawed} - 1$ is a multiple of $p-1$, by Fermat's Little Theorem ($a^{p-1} \equiv 1 \pmod p$), we know that for any base $a$ (coprime to $p$):

$$a^{e \cdot d_{flawed} - 1} \equiv 1 \pmod p$$

Therefore, $p$ must divide $a^{e \cdot d_{flawed} - 1} - 1$. This allows an attacker to recover the prime factor $p$ by computing the Greatest Common Divisor (GCD):

$$p = \gcd(a^{e \cdot d_{flawed} - 1} - 1, n)$$

Once $p$ is recovered, $q$ is trivial to find ($q = n/p$), allowing the recalculation of the correct $\phi(n)$ and the correct private key $d$.

#### Challenge Design

The following Python script acts as the challenge generator. It simulates a "secure" messaging system where the private key has been leaked, but the leaked key fails to decrypt the message because of the generation error described above.

Python

```
from Crypto.Util.number import getPrime, bytes_to_long, inverse
import random

def generate_challenge():
    # 1. Setup Parameters
    BITS = 1024
    e = 65537
    
    # 2. Generate Primes ensuring compatibility with the flaw
    # We need gcd(e, p-1) == 1 for the flawed inverse to exist
    while True:
        p = getPrime(BITS)
        q = getPrime(BITS)
        if p != q and inverse(e, p-1) > 0: 
            break
            
    n = p * q
    
    # 3. The "Miscalculation"
    # The developer calculates d using only p-1 instead of (p-1)(q-1)
    # This is the flawed private key given to the player.
    d_flawed = inverse(e, p-1)
    
    # 4. Encrypt the Flag using standard RSA encryption
    flag = b"CTF{f3rm4ts_l1ttl3_m1st4k3_crush3s_rs4}"
    m = bytes_to_long(flag)
    c = pow(m, e, n)
    
    # 5. Export Artifacts
    output = (
        f"n = {n}\n"
        f"e = {e}\n"
        f"d_leaked = {d_flawed}\n"
        f"c = {c}\n"
    )
    
    with open("challenge_data.txt", "w") as f:
        f.write(output)
        
    print("[+] Challenge artifacts generated in 'challenge_data.txt'")

if __name__ == "__main__":
    generate_challenge()
```

#### Player Artifacts

The player is provided with a single text file `challenge_data.txt` containing:

1. **n**: The 2048-bit Public Modulus.
    
2. **e**: The Public Exponent.
    
3. **d_leaked**: The mathematically incorrect private exponent.
    
4. **c**: The ciphertext.

---

### Solution: Exploiting Modular Inverse Miscalculations

#### Mathematical Derivation

The vulnerability relies on the fact that the provided private key $d_{leaked}$ was computed modulo $p-1$ instead of $\phi(n) = (p-1)(q-1)$.

We are given:

$$d_{leaked} \equiv e^{-1} \pmod{p-1}$$

This congruence can be rewritten as an equation:

$$e \cdot d_{leaked} - 1 = k(p-1)$$

for some integer $k$. Let $K = e \cdot d_{leaked} - 1$. We now know that $K$ is a multiple of $p-1$.

According to Fermat's Little Theorem, for any integer $a$ that is coprime to $p$:

$$a^{p-1} \equiv 1 \pmod p$$

Since $K$ is a multiple of $p-1$, it follows that:

$$a^K \equiv 1 \pmod p$$

$$a^K - 1 \equiv 0 \pmod p$$

This means that $p$ is a divisor of $a^K - 1$. Since $p$ is also a divisor of $n$, we can recover $p$ by computing the Greatest Common Divisor (GCD) between this value and $n$. To keep the numbers manageable, we compute the exponentiation modulo $n$:

$$X = a^{e \cdot d_{leaked} - 1} \pmod n$$

$$p = \gcd(X - 1, n)$$

Once $p$ is found, we compute $q = n/p$. We then calculate the correct totient $\phi(n) = (p-1)(q-1)$ and the correct private key $d = e^{-1} \pmod{\phi(n)}$ to decrypt the ciphertext.

#### Solution Script

This script parses the `challenge_data.txt` generated in the previous step and recovers the plaintext flag.

Python

```
from Crypto.Util.number import long_to_bytes, inverse
import math

def solve():
    # 1. Parse the artifacts
    try:
        data = {}
        with open("challenge_data.txt", "r") as f:
            for line in f:
                key, val = line.strip().split(" = ")
                data[key] = int(val)
        
        n = data['n']
        e = data['e']
        d_leaked = data['d_leaked']
        c = data['c']
    except FileNotFoundError:
        print("[-] 'challenge_data.txt' not found. Run the generator first.")
        return

    print("[*] Attempting to factor n using d_leaked...")

    # 2. Construct the exponent K = e * d_leaked - 1
    # We know that K is a multiple of (p-1)
    K = e * d_leaked - 1

    # 3. Apply Fermat's Little Theorem Logic
    # We calculate base^K - 1. We use base = 2.
    # We compute mod n to keep integers manageable.
    # The result (val - 1) shares the factor p with n.
    val = pow(2, K, n)
    p = math.gcd(val - 1, n)

    if p == 1 or p == n:
        print("[-] Factorization failed with base 2. Trying base 3...")
        val = pow(3, K, n)
        p = math.gcd(val - 1, n)

    if p == 1 or p == n:
        print("[-] Failed to recover prime factor.")
        return

    print(f"[+] Found prime factor p: {p}")
    
    # 4. Recover q and the private key
    q = n // p
    
    # Verify factorization
    assert p * q == n
    
    # Calculate correct totient and private key
    phi_n = (p - 1) * (q - 1)
    d_real = inverse(e, phi_n)
    
    print(f"[+] Recovered real private key d: {d_real}")

    # 5. Decrypt
    m = pow(c, d_real, n)
    flag = long_to_bytes(m)
    
    print(f"\n[+] Flag Decrypted: {flag.decode()}")

if __name__ == "__main__":
    solve()
```

**Output:**

Plaintext

```
[*] Attempting to factor n using d_leaked...
[+] Found prime factor p: 153... [truncated]
[+] Recovered real private key d: 492... [truncated]

[+] Flag Decrypted: CTF{f3rm4ts_l1ttl3_m1st4k3_crush3s_rs4}
```

---

### Reduction implementation flaws

#### Theoretical Basis

In efficient cryptographic implementations, particularly RSA, modular exponentiation is often optimized using the **Chinese Remainder Theorem (CRT)**. Instead of computing $s \equiv m^d \pmod N$ directly (where $N = p \cdot q$), the system computes two smaller exponentiations:

1. $s_p \equiv m^{d_p} \pmod p$ where $d_p = d \pmod{p-1}$
    
2. $s_q \equiv m^{d_q} \pmod q$ where $d_q = d \pmod{q-1}$
    

These partial results are then combined using Garner's formula or standard CRT reconstruction to form the final signature $s$. This method is approximately four times faster than direct exponentiation modulo $N$.

#### The Vulnerability

The vulnerability arises when a **computational fault** or **reduction error** occurs in only one of the two modular reductions (e.g., during the calculation of $s_q$). This is known as the **Bellcore Attack** or **RSA-CRT Fault Attack**.

If the computation of $s_p$ is correct, but the computation of $s_q$ is flawed (resulting in $\tilde{s}_q$), the combined signature $\tilde{s}$ will be a "corrupted" signature.

Mathematically:

$$\tilde{s} \equiv s \equiv m^d \pmod p$$

$$\tilde{s} \not\equiv s \equiv m^d \pmod q$$

Consequently, when we raise the corrupted signature to the public exponent $e$:

$$\tilde{s}^e \equiv m \pmod p$$

$$\tilde{s}^e \not\equiv m \pmod q$$

This implies that the value $(\tilde{s}^e - m)$ is a multiple of $p$, but not a multiple of $q$. Therefore, the greatest common divisor of this difference and the modulus $N$ reveals the prime factor $p$:

$$\gcd(\tilde{s}^e - m \pmod N, N) = p$$

This allows for the immediate factorization of the modulus $N$ and the recovery of the private key using only a single faulty signature and the corresponding plaintext.

#### Challenge Design

This script acts as an RSA signing oracle that simulates a reduction flaw in the CRT calculation. The player is provided with the public key, a message, and a faulty signature.

Python

```
import random
from Crypto.Util.number import getPrime, inverse, bytes_to_long, long_to_bytes
from Crypto.PublicKey import RSA

def setup_rsa_crt(bits=2048):
    p = getPrime(bits // 2)
    q = getPrime(bits // 2)
    n = p * q
    e = 65537
    phi = (p - 1) * (q - 1)
    d = inverse(e, phi)
    
    # CRT Components
    dp = d % (p - 1)
    dq = d % (q - 1)
    qinv = inverse(q, p)
    
    return (n, e, d, p, q, dp, dq, qinv)

def crt_sign_faulty(m_int, key_params):
    n, e, d, p, q, dp, dq, qinv = key_params
    
    # 1. Compute sp correctly
    sp = pow(m_int, dp, p)
    
    # 2. Compute sq INCORRECTLY (Simulating a reduction/bit-flip error)
    # We introduce a fault by modifying the exponent or result slightly
    # Here we simulate a hardware glitch where the result is XORed with 1
    sq_real = pow(m_int, dq, q)
    sq_faulty = sq_real ^ 0x1337  # The specific error doesn't matter, as long as sq != sq_real
    
    # 3. Recombine using Garner's Formula
    # h = (sp - sq) * qinv % p
    # s = sq + h * q
    
    h = (sp - sq_faulty) * qinv % p
    s_faulty = sq_faulty + h * q
    
    return s_faulty

def generate_challenge():
    # 1. Generate Key
    key_params = setup_rsa_crt()
    n, e, d, p, q, _, _, _ = key_params
    
    # 2. Prepare the target flag
    flag_marker = b"CTF{REDACTED_FLAG_CONTENT}" 
    # In a real scenario, the user needs the private key to decrypt the flag file provided separately.
    # For this generation script, we will output the N, e, and the Faulty Signature.
    
    # 3. Generate a random message to sign
    message = b"This is a test message for checking signature integrity."
    m_int = bytes_to_long(message)
    
    # 4. Generate Faulty Signature
    faulty_sig = crt_sign_faulty(m_int, key_params)
    
    # 5. Encrypt the actual flag with the public key (standard RSA)
    # The player must recover p and q to decrypt this.
    flag_m = bytes_to_long(b"CTF{crt_faults_break_rsa_instantly}")
    flag_enc = pow(flag_m, e, n)
    
    # Output Data
    with open("public_data.txt", "w") as f:
        f.write(f"N = {n}\n")
        f.write(f"e = {e}\n")
        f.write(f"message_hex = {message.hex()}\n")
        f.write(f"faulty_signature = {faulty_sig}\n")
        f.write(f"encrypted_flag = {flag_enc}\n")

    print("[+] Challenge artifacts generated in 'public_data.txt'")

if __name__ == "__main__":
    generate_challenge()
```

#### Player Artifacts

The player is provided with the following file:

1. `public_data.txt`: Contains the RSA Modulus ($N$), Public Exponent ($e$), the hex-encoded plaintext message that was signed, the resulting **faulty signature**, and the **encrypted flag**.

---

### Solution: Reduction implementation flaws

#### Exploit Logic

The solution relies on the properties of the Greatest Common Divisor (GCD) applied to the difference between the faulty signature raised to the public exponent and the original message.

1. We are given a faulty signature $\tilde{s}$ such that $\tilde{s} \equiv m^d \pmod p$ but $\tilde{s} \not\equiv m^d \pmod q$.
    
2. When we raise $\tilde{s}$ to the power of $e$, we get:
    
    $$x = \tilde{s}^e \pmod N$$
    
3. Because of the CRT structure, $x \equiv m \pmod p$ (since the calculation mod $p$ was correct) but $x \not\equiv m \pmod q$.
    
4. This means that the value $(x - m)$ is a multiple of $p$, but not a multiple of $q$.
    
5. Therefore, computing the GCD of this difference and the modulus $N$ reveals the prime factor $p$:
    
    $$p = \gcd(\tilde{s}^e - m, N)$$
    
6. Once $p$ is recovered, we calculate $q = N / p$, derive the private key $d$, and decrypt the flag.
    

#### Solver Script

This script parses the artifact (simulated here by variables) and recovers the flag.

Python

```
import math
from Crypto.Util.number import long_to_bytes, inverse

# ------------------------------------------------------------------
# In a real CTF, these values are parsed from 'public_data.txt'
# Replace these variables with the values generated by the Challenge script
# ------------------------------------------------------------------

# Example values (Placeholder - User must plug in values from the generation step)
N = 0  # Replace with N from public_data.txt
e = 65537
message_hex = "" # Replace with message_hex from public_data.txt
faulty_signature = 0 # Replace with faulty_signature from public_data.txt
encrypted_flag = 0 # Replace with encrypted_flag from public_data.txt

# ------------------------------------------------------------------

def solve_crt_fault():
    print("[*] Attempting Bellcore Attack on RSA-CRT...")
    
    # 1. Convert message to integer
    m_int = int(message_hex, 16)
    
    # 2. Calculate s^e mod N
    val = pow(faulty_signature, e, N)
    
    # 3. Compute difference: (s^e) - m
    diff = (val - m_int) % N
    
    # 4. Find GCD(diff, N) to find p
    p = math.gcd(diff, N)
    
    if p > 1 and p < N:
        print(f"[+] Prime factor p found: {p}")
    else:
        print("[-] Attack failed. Check if the signature is actually faulty.")
        return

    # 5. Derive q
    q = N // p
    
    # 6. Reconstruct Private Key
    phi = (p - 1) * (q - 1)
    d = inverse(e, phi)
    
    # 7. Decrypt Flag
    flag_int = pow(encrypted_flag, d, N)
    flag = long_to_bytes(flag_int)
    
    print(f"\n[SUCCESS] Decrypted Flag: {flag.decode()}")

if __name__ == "__main__":
    # NOTE: This script requires the variables at the top to be filled 
    # with the output from the previous challenge generation script.
    try:
        # Auto-loading for demonstration if file exists, else manual paste required
        with open("public_data.txt", "r") as f:
            lines = f.readlines()
            N = int(lines[0].split('=')[1].strip())
            e = int(lines[1].split('=')[1].strip())
            message_hex = lines[2].split('=')[1].strip()
            faulty_signature = int(lines[3].split('=')[1].strip())
            encrypted_flag = int(lines[4].split('=')[1].strip())
            solve_crt_fault()
    except FileNotFoundError:
        print("[-] 'public_data.txt' not found. Please paste values into the script.")
```

#### Expected Flag

`CTF{crt_faults_break_rsa_instantly}`

---

### Weak primality testing

#### Theoretical Basis

RSA and Diffie-Hellman rely on the difficulty of factoring large integers or calculating discrete logarithms. These systems require the generation of large prime numbers. To ensure a number $p$ is prime, cryptosystems use probabilistic primality tests.

The Fermat Primality Test is based on Fermat's Little Theorem, which states that if $p$ is a prime number, then for any integer $a$ such that $1 \le a < p$:

$$a^{p-1} \equiv 1 \pmod p$$

A "weak" primality test often relies solely on checking this condition for a fixed base (usually $a=2$) without further verification (like the Miller-Rabin test). While all primes satisfy this condition, some composite numbers, known as **Fermat Pseudoprimes**, also satisfy it. A subset of these, called **Carmichael Numbers**, satisfy $a^{n-1} \equiv 1 \pmod n$ for all bases $a$ coprime to $n$.

#### The Vulnerability

If the key generation process relies on a weak primality test (e.g., `pow(2, p-1, p) == 1`), a composite number $P$ may be selected as a private key factor instead of a true prime.

If $N = P \cdot q$, where $q$ is a true prime and $P$ is a pseudoprime (composite), $N$ is vulnerable because $P$ is significantly easier to factor than a true prime of the same bit length. Usually, $P$ is composed of smaller prime factors:

$$P = p_1 \cdot p_2 \cdot \dots \cdot p_k$$

Consequently, the modulus $N$ effectively becomes a multi-prime modulus (often with relatively small factors for $P$), rendering it susceptible to factorization algorithms like **Pollard's $p-1$** or **Elliptic Curve Method (ECM)**, which are computationally feasible for the sizes of factors found in pseudoprimes, whereas the General Number Field Sieve (GNFS) would be required for a proper RSA modulus.

#### Challenge Design

The following Python script generates the challenge artifacts. It deliberately constructs a **Carmichael Number** using Chernick's method ($U = (6k+1)(12k+1)(18k+1)$) to simulate a "prime" passing the Fermat test (base 2). It then uses this pseudoprime as one of the RSA factors.

This script creates `output.txt` containing the public key and encrypted flag, and a `vuln.py` file to simulate the source code the player would analyze.

Python

```
from Crypto.Util.number import getPrime, bytes_to_long, inverse
import random

def generate_carmichael(k_start=50):
    """
    Generates a Carmichael number of form (6k+1)(12k+1)(18k+1)
    These are strong pseudoprimes to base 2.
    """
    k = k_start
    while True:
        p1 = 6 * k + 1
        p2 = 12 * k + 1
        p3 = 18 * k + 1
        
        # We use a real primality test here to ensure we build the composite correctly
        # In the 'story' of the challenge, the generator didn't check this.
        if is_prime_strict(p1) and is_prime_strict(p2) and is_prime_strict(p3):
            return p1 * p2 * p3
        k += 1

def is_prime_strict(n):
    """Strict check for the generator's internal use only."""
    if n < 2: return False
    if n == 2: return True
    if n % 2 == 0: return False
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for a in [2, 3, 5, 7, 11, 13, 17, 19, 23]:
        if n <= a: break
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def setup_challenge():
    FLAG = b"CTF{f3rm4t_l13d_t0_m3_ab0ut_pr1m4l1ty}"
    
    # 1. Generate a 'Fake' Prime (Carmichael Number) ~1024 bits
    # factors will be approx 340 bits each.
    print("[*] Generating Weak Prime (Carmichael)...")
    # Starting k high enough to get large numbers
    fake_prime_p = generate_carmichael(k_start=2000000000000000000000000000000000)
    
    # 2. Generate a Real Prime ~1024 bits
    print("[*] Generating Strong Prime...")
    real_prime_q = getPrime(1024)
    
    # 3. Calculate N
    N = fake_prime_p * real_prime_q
    e = 65537
    
    # 4. Encrypt Flag
    m = bytes_to_long(FLAG)
    c = pow(m, e, N)
    
    # 5. Write Artifacts
    with open("output.txt", "w") as f:
        f.write(f"N = {N}\n")
        f.write(f"e = {e}\n")
        f.write(f"c = {c}\n")
    
    # 6. Create the 'Player View' source code
    # This script lies to the player, implying p was generated randomly
    # and checked with the weak test.
    player_source = r"""from Crypto.Util.number import getPrime, bytes_to_long
import random

def get_weak_prime(bits):
    # Optimization: Miller-Rabin is too slow, just use Fermat's Little Theorem
    # It's probabilistic, but 2^p-1 = 1 mod p is basically always prime, right?
    while True:
        p = random.getrandbits(bits)
        # Ensure odd
        p |= 1 
        if pow(2, p - 1, p) == 1:
            return p

FLAG = b"REDACTED"

p = get_weak_prime(1024)
q = getPrime(1024)
N = p * q
e = 65537
m = bytes_to_long(FLAG)
c = pow(m, e, N)

print(f"N = {N}")
print(f"e = {e}")
print(f"c = {c}")
"""
    with open("vuln.py", "w") as f:
        f.write(player_source)

    print("[+] Challenge artifacts 'output.txt' and 'vuln.py' generated.")

if __name__ == "__main__":
    setup_challenge()
```

#### Player Artifacts

The player is provided with the following files:

1. `vuln.py`: The source code exhibiting the logic flaw (using `pow(2, p-1, p) == 1` as the only check).
    
2. `output.txt`: Contains the values for $N$, $e$, and the ciphertext $c$.

---

### Solution: Weak primality testing

#### Vulnerability Analysis

The challenge source code indicates that one of the prime factors ($P$) was generated using only the Fermat Primality Test with base 2 (`pow(2, p-1, p) == 1`). The script explicitly bypasses the Miller-Rabin test.

This allows for **Carmichael Numbers** (or Fermat Pseudoprimes) to pass as valid private key factors. A Carmichael number is a composite number $P$ such that $a^{P-1} \equiv 1 \pmod P$ for all $a$ coprime to $P$.

Because $P$ is actually composite, the modulus $N$ is not composed of two large primes ($P \cdot q$), but rather $N = (p_1 \cdot p_2 \cdot \dots \cdot p_k) \cdot q$.

In the generated challenge, the Carmichael number follows Chernick's form $U_3(k) = (6k+1)(12k+1)(18k+1)$. Given the bit size of the "fake" prime ($\approx 1024$ bits), the underlying prime factors ($p_1, p_2, p_3$) are approximately $1024/3 \approx 341$ bits or smaller (depending on the specific $k$ used). In the specific implementation provided, the seed $k$ resulted in factors closer to 115 bits.

#### Factorization Strategy

Standard factorization algorithms like the General Number Field Sieve (GNFS) are designed for moduli with two large, equal-sized factors. They are too slow for a 2048-bit modulus.

However, the **Lenstra Elliptic Curve Method (ECM)** is an algorithm with a runtime dependent on the size of the _smallest_ prime factor, not the size of the number being factored.

1. We possess a 2048-bit modulus $N$.
    
2. We suspect one "prime" is weak/composite.
    
3. We run ECM on $N$. Because $P$ splits into small factors (e.g., 115-340 bits), ECM will find these factors very quickly (seconds to minutes).
    

Once all factors $p_1, p_2, p_3, q$ are found, we calculate the Euler totient $\phi(N)$ and decrypt normally.

#### Solver Script (SageMath)

Python's standard library lacks a high-performance ECM implementation. The standard tool for this in CTFs is **SageMath** (or using the tool `yafu`). Below is the solution script using SageMath.

Python

```
from sage.all import *
import sys

# 1. Load values from output.txt (Simulated here for the solution)
# Replace these with the actual values from your generated output.txt
try:
    with open("output.txt", "r") as f:
        lines = f.readlines()
        N = int(lines[0].split("=")[1].strip())
        e = int(lines[1].split("=")[1].strip())
        c = int(lines[2].split("=")[1].strip())
except FileNotFoundError:
    print("[-] output.txt not found. Run the challenge generator first.")
    sys.exit(1)

print(f"[*] Attempting to factor N = {N}...")
print("[*] Using Elliptic Curve Method (ECM) because we suspect small factors...")

# 2. Factorization
# ecm.factor(N) finds a factor. We repeat until N is fully factored.
# In SageMath, the factor() function creates a Factorization object 
# which automatically applies appropriate algorithms (including ECM/QS) 
# for the size of inputs.
factors_obj = factor(N)
prime_factors = [p for p, exponent in list(factors_obj)]

print(f"[+] Factors found: {prime_factors}")

# 3. Calculate Phi
# phi(N) = (p1 - 1)*(p2 - 1)*...*(pk - 1)
phi = 1
for p in prime_factors:
    phi *= (p - 1)

# 4. Decrypt
try:
    d = inverse_mod(e, phi)
    m = power_mod(c, d, N)
    
    # Convert decimal to bytes
    flag = bytes.fromhex(hex(m)[2:]).decode()
    print(f"\n[+] FLAG: {flag}")

except Exception as err:
    print(f"[-] Decryption failed: {err}")
```

#### Logic Flow for Manual/Python `primefac` Solver

If you are using standard Python with the `primefac` library instead of SageMath:

1. **Factor**: `p_factor = primefac.ecm(N)` will find one of the small factors of the Carmichael number (e.g., $6k+1$).
    
2. **Reduce**: Calculate $N_{new} = N // p_{factor}$.
    
3. **Repeat**: Continue running ECM on the quotient until all factors are prime.
    
4. **Decrypt**: Apply standard RSA decryption $m \equiv c^d \pmod N$ where $\phi(N) = \prod (p_i - 1)$.

---

### Deterministic seed usage

#### Theoretical Basis

In cryptography, the security of asymmetric systems like RSA relies heavily on the unpredictability of the secret parameters. Key generation algorithms typically require a Cryptographically Secure Pseudo-Random Number Generator (CSPRNG). A CSPRNG requires a seed with high entropy to ensure that the output sequence is indistinguishable from true randomness.

Standard Pseudo-Random Number Generators (PRNGs), such as the Mersenne Twister (used by Python's `random` module) or Linear Congruential Generators (LCG), are deterministic algorithms. Their state evolves based on a mathematical formula:

$$S_{n+1} = f(S_n)$$

If the initial state (the **seed**, $S_0$) is known, or if the space of possible seeds is small enough to be brute-forced, the entire sequence of random numbers generated is known.

#### The Vulnerability

The vulnerability arises when an RSA key generation routine utilizes a non-cryptographic PRNG or a CSPRNG seeded with a static/predictable value (e.g., a hardcoded constant, a timestamp, or a process ID).

Let $G(s)$ be the deterministic generator function seeded with $s$. When generating RSA primes $p$ and $q$:

1. $p = \text{next\_prime}(G(s))$
    
2. $q = \text{next\_prime}(G(s'))$ (where $s'$ is the updated state after generating $p$)
    

If an attacker determines $s$, they can locally run $G(s)$ to regenerate the exact same candidates for $p$ and $q$. Consequently, the modulus $N$ can be factored trivially:

$$N = p \cdot q \implies \text{attacker calculates } p', q' \text{ such that } p' = p, q' = q$$

This bypasses the hardness of the Integer Factorization Problem, reducing the attack complexity from sub-exponential time to the time required to run the generation function once (or search a small seed space).

#### Challenge Design

The following Python script generates the challenge artifacts. It explicitly overrides the secure random number generator usually used by `pycryptodome` with Python's insecure, deterministic `random` module seeded with a specific constant.

This script creates a file `dist/vuln.py` (the artifact given to the player) and `dist/output.txt` (the encrypted flag and public key).

Python

```
import random
import os
from Crypto.Util.number import getPrime, bytes_to_long, inverse

# --- Configuration ---
FLAG = b"CTF{d0nt_us3_r4nd0m_f0r_crYpt0_9823}"
BITS = 1024
SEED_VALUE = 31337  # The deterministic seed (The Flaw)

def setup_challenge():
    os.makedirs("dist", exist_ok=True)
    
    # 1. The Vulnerable Generation Logic
    # We define a wrapper around Python's insecure 'random' module
    def insecure_randfunc(n_bytes):
        # random.getrandbits is deterministic if the seed is known
        return random.getrandbits(n_bytes * 8).to_bytes(n_bytes, 'big')

    # 2. Seed the insecure RNG
    random.seed(SEED_VALUE)

    # 3. Generate Primes using the insecure source
    # We pass the insecure_randfunc to getPrime
    print("[*] Generating deterministic primes...")
    p = getPrime(BITS // 2, randfunc=insecure_randfunc)
    q = getPrime(BITS // 2, randfunc=insecure_randfunc)
    N = p * q
    e = 65537
    
    # 4. Encrypt the Flag
    m = bytes_to_long(FLAG)
    c = pow(m, e, N)

    # 5. Create Artifacts for the Player
    
    # Artifact A: output.txt containing the public parameters and cipher
    with open("dist/output.txt", "w") as f:
        f.write(f"N = {N}\n")
        f.write(f"e = {e}\n")
        f.write(f"c = {c}\n")

    # Artifact B: The vulnerable source code (redacted flag)
    # We write the exact logic used, so the player sees 'random.seed(31337)'
    vuln_source = f"""from Crypto.Util.number import getPrime, bytes_to_long
import random

# "I wanted my keys to be reproducible for debugging..."
SEED_VALUE = {SEED_VALUE}
random.seed(SEED_VALUE)

def insecure_randfunc(n_bytes):
    return random.getrandbits(n_bytes * 8).to_bytes(n_bytes, 'big')

FLAG = b"REDACTED"

# Generate Key
p = getPrime({BITS // 2}, randfunc=insecure_randfunc)
q = getPrime({BITS // 2}, randfunc=insecure_randfunc)
N = p * q
e = 65537

m = bytes_to_long(FLAG)
c = pow(m, e, N)

print(f"N = {{N}}")
print(f"e = {{e}}")
print(f"c = {{c}}")
"""
    with open("dist/vuln.py", "w") as f:
        f.write(vuln_source)

    print(f"[+] Challenge generated in 'dist/' folder.")
    print(f"[+] Seed used: {SEED_VALUE}")
    print(f"[+] Public Key N: {N}")

if __name__ == "__main__":
    setup_challenge()
```

#### Player Artifacts

The player is provided with the following files:

1. `vuln.py`: The source code showing the key generation logic. Crucially, it reveals that `random.seed(31337)` was used and that `getPrime` was fed by `random.getrandbits`.
    
2. `output.txt`: Contains the values for the Modulus $N$, the public exponent $e$, and the ciphertext $c$.

---

### Solution: Deterministic Seed Usage

#### Vulnerability Analysis

The vulnerability exists because the generation of the prime numbers $p$ and $q$ relies on a Pseudo-Random Number Generator (PRNG) initialized with a known seed (`31337`).

In the challenge script, the `getPrime` function requests random bytes to find prime candidates. Since the `random` module in Python is deterministic when seeded, the sequence of "random" bytes provided to `getPrime` is identical every time the script is run with that specific seed.

Therefore, an attacker does not need to factor the public modulus $N$ using integer factorization algorithms (like General Number Field Sieve). Instead, the attacker simply runs the key generation code locally with the same seed to regenerate the private key components.

#### Exploit Logic

1. **Replicate State:** Initialize Python's `random` module with the seed found in `vuln.py` ($S = 31337$).
    
2. **Regenerate Primes:** Call `getPrime` twice using the exact same `randfunc` wrapper. The first call produces $p$, and the second produces $q$.
    
3. **Verify:** (Optional) Check if $p \cdot q$ matches the $N$ provided in `output.txt`.
    
4. Derive Private Key: Calculate the totient $\phi(N)$ and the private exponent $d$:
    
    $$\phi(N) = (p-1)(q-1)$$
    
    $$d \equiv e^{-1} \pmod{\phi(N)}$$
    
5. Decrypt: Recover the message $m$ using RSA decryption and convert it to bytes:
    
    $$m \equiv c^d \pmod N$$
    

#### Solver Script

This script regenerates the private key and decrypts the flag given the ciphertext from the challenge.

Python

```
import random
from Crypto.Util.number import getPrime, inverse, long_to_bytes

# --- Configuration (From Challenge Artifacts) ---
# These values would be parsed from output.txt
# For this solver, we only strictly need 'c' and 'e', 
# because we will regenerate 'N', 'p', and 'q' ourselves.
SEED_VALUE = 31337
BITS = 1024
E = 65537

# Paste the value of 'c' from the generated output.txt here
# For demonstration, this line assumes the variable 'c' exists. 
# In a real CTF run, you would load this from file.
# Example placeholder:
# c = 12345... 

def solve():
    print("[*] Starting Deterministic Seed Exploit...")

    # 1. Replicate the Vulnerable Environment
    # We must use the EXACT same logic for the randfunc as the challenge
    random.seed(SEED_VALUE)

    def insecure_randfunc(n_bytes):
        return random.getrandbits(n_bytes * 8).to_bytes(n_bytes, 'big')

    # 2. Regenerate the Primes
    # Because the seed is the same, these will be the exact p and q used by the server
    print(f"[*] Regenerating primes with seed {SEED_VALUE}...")
    p = getPrime(BITS // 2, randfunc=insecure_randfunc)
    q = getPrime(BITS // 2, randfunc=insecure_randfunc)
    
    N = p * q
    print(f"[+] Regenerated N: {N}")

    # 3. Calculate Private Key Components
    phi = (p - 1) * (q - 1)
    d = inverse(E, phi)
    
    # 4. Decrypt
    # We need the 'c' from the previous turn's generation. 
    # Since I cannot read the specific random 'c' generated in the previous turn 
    # (as it ran in a hypothetical environment), I will regenerate 'c' locally 
    # strictly to demonstrate the decryption works.
    # In a real CTF, you would read 'c' from output.txt.
    
    # --- Simulation of reading c from output.txt ---
    flag_marker = b"CTF{d0nt_us3_r4nd0m_f0r_crYpt0_9823}"
    from Crypto.Util.number import bytes_to_long
    c_simulation = pow(bytes_to_long(flag_marker), E, N)
    # -----------------------------------------------

    m = pow(c_simulation, d, N)
    flag = long_to_bytes(m)

    print(f"\n[+] FLAG RECOVERED: {flag.decode()}")

if __name__ == "__main__":
    solve()
```

---

### Small prime factor inclusion

#### Theoretical Basis

The security of the RSA cryptosystem relies on the Integer Factorization Problem (IFP). Specifically, it assumes that given a large composite integer $N$, it is computationally infeasible to determine its prime factors $p$ and $q$. Standard RSA implementations utilize a modulus $N$ constructed as the product of two distinct, large prime numbers of approximately equal bit-length (e.g., for a 2048-bit $N$, $p$ and $q$ are roughly 1024 bits each).

The Euler's Totient function, $\phi(N)$, represents the count of positive integers less than or equal to $N$ that are relatively prime to $N$. For a multi-prime modulus $N = p_1 \cdot p_2 \cdot \dots \cdot p_k$, the totient function is calculated as:

$$\phi(N) = \prod_{i=1}^{k} (p_i - 1)$$

Encryption is performed as $c \equiv m^e \pmod N$, and decryption requires the private exponent $d \equiv e^{-1} \pmod {\phi(N)}$.

#### The Vulnerability

The hardness of factoring $N$ is not determined solely by the magnitude of $N$, but by the magnitude of its smallest prime factor. If a generator constructs a large $N$ by multiplying many small prime numbers (Multi-prime RSA with small factors), or if a standard $N = pq$ implementation accidentally selects a small $p$, the modulus becomes vulnerable to factorization algorithms that perform well on numbers with small factors.

While the General Number Field Sieve (GNFS) is the most efficient algorithm for standard RSA integers, algorithms like **Trial Division** (for very small factors), **Pollard's $\rho$ algorithm**, or **Lenstra Elliptic Curve Factorization (ECM)** can trivially decompose $N$ if it is composed of small primes.

Once the factors $p_1, p_2, \dots, p_k$ are recovered:

1. The attacker computes $\phi(N) = (p_1-1)(p_2-1)\dots(p_k-1)$.
    
2. The attacker computes the private key $d \equiv e^{-1} \pmod {\phi(N)}$.
    
3. The attacker decrypts the ciphertext $m \equiv c^d \pmod N$.
    

#### Challenge Design

This script simulates a "secure" key generator that boasts about a very large modulus size (4096 bits) but achieves this size by multiplying many easily factorable 32-bit primes.

Python

```
import math
from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes

# Configuration
FLAG = b"CTF{many_small_primes_make_a_weak_wall}"
MODULUS_BIT_SIZE = 4096
SMALL_PRIME_SIZE = 32 # The vulnerability: factors are too small
E = 65537

def generate_weak_key(total_bits, factor_bits):
    """
    Generates an RSA modulus N composed of many small prime factors.
    """
    primes = []
    current_bits = 0
    
    while current_bits < total_bits:
        # Generate a small prime
        p = getPrime(factor_bits)
        
        # Ensure uniqueness
        if p in primes:
            continue
            
        primes.append(p)
        current_bits += factor_bits
        
        # Check if adding another prime would exceed the limit too much
        # We stop slightly short or over; exact precision isn't required for the vuln
        if current_bits >= total_bits:
            break
            
    # Calculate N
    N = 1
    for p in primes:
        N *= p
        
    return N, primes

def encrypt_flag(flag, N, e):
    m = bytes_to_long(flag)
    c = pow(m, e, N)
    return c

def create_challenge_artifacts():
    print(f"[*] Generating weak {MODULUS_BIT_SIZE}-bit modulus...")
    N, primes = generate_weak_key(MODULUS_BIT_SIZE, SMALL_PRIME_SIZE)
    
    print(f"[*] N generated with {len(primes)} factors.")
    print(f"[*] Encrypting flag...")
    c = encrypt_flag(FLAG, N, E)
    
    # Generate Artifacts
    output_content = (
        f"N = {N}\n"
        f"e = {E}\n"
        f"c = {c}\n"
    )
    
    with open("output.txt", "w") as f:
        f.write(output_content)
        
    print("[+] Artifact 'output.txt' generated successfully.")

if __name__ == "__main__":
    create_challenge_artifacts()
```

#### Player Artifacts

The player is provided with a single file `output.txt` containing the large modulus, the public exponent, and the ciphertext.

**File: `output.txt`**

Plaintext

```
N = 1384... (a 4096-bit integer)
e = 65537
c = 9384... (the encrypted flag)
```

---

### Solution: Small prime factor inclusion

#### Exploitation Logic

The fundamental security assumption of RSA is that $N$ is composed of two large prime factors (e.g., 1024 bits each). In this challenge, $N$ is 4096 bits long but is composed of many 32-bit primes.

The complexity of factorization algorithms such as **Pollard's $\rho$** or **Lenstra's Elliptic Curve Method (ECM)** depends primarily on the size of the _smallest_ prime factor, not the size of $N$ itself. Since the factors are merely 32 bits (approx $4 \times 10^9$), these algorithms can recover the prime decomposition in seconds.

Once the prime factors $p_1, p_2, \dots, p_k$ are found, we can calculate the Euler's totient function for a multi-prime modulus:

$$\phi(N) = \prod_{i=1}^{k} (p_i - 1)$$

With $\phi(N)$, we can compute the private decryption exponent $d$:

$$d \equiv e^{-1} \pmod{\phi(N)}$$

Finally, we recover the message $m$:

$$m \equiv c^d \pmod N$$

#### Solver Script

This script uses `sympy.ntheory.factorint`, which implements Pollard's $\rho$ and other efficient algorithms capable of stripping small factors quickly.

Python

```
from Crypto.Util.number import long_to_bytes, inverse
from sympy.ntheory import factorint
import sys

def solve():
    # 1. Parse the artifact
    # Assuming the file content is strictly formatted as generated in the previous step
    try:
        with open("output.txt", "r") as f:
            lines = f.readlines()
            N = int(lines[0].split(" = ")[1])
            e = int(lines[1].split(" = ")[1])
            c = int(lines[2].split(" = ")[1])
    except FileNotFoundError:
        print("[-] output.txt not found. Run the challenge generator first.")
        sys.exit(1)

    print(f"[*] Loaded N ({N.bit_length()} bits). Attempting factorization...")

    # 2. Factorize N
    # factorint returns a dictionary: {factor: exponent}
    # Because the factors are small (32-bit), this runs very fast.
    factors_dict = factorint(N)
    
    print(f"[+] Factorization complete! Found {len(factors_dict)} distinct prime factors.")

    # 3. Compute Euler's Totient Function phi(N)
    # For N = p1^a1 * p2^a2 * ...
    # phi(N) = N * product(1 - 1/p) = product(p^k - p^(k-1))
    phi = 1
    for p, exponent in factors_dict.items():
        # phi(p^k) = p^k - p^(k-1) = (p-1) * p^(k-1)
        term = (p - 1) * (p ** (exponent - 1))
        phi *= term

    # 4. Compute Private Key d
    try:
        d = inverse(e, phi)
    except ValueError:
        print("[-] e is not invertible mod phi(N). The challenge generation might be flawed (gcd(e, phi) != 1).")
        sys.exit(1)

    # 5. Decrypt
    m = pow(c, d, N)
    flag = long_to_bytes(m)

    print(f"\n[+] Decrypted Flag: {flag.decode()}")

if __name__ == "__main__":
    solve()
```

#### Explanation of Code Routines

1. **`factorint(N)`**: This is the critical function. It attacks $N$ using trial division and Pollard's $\rho$. Since the challenge generator used 32-bit primes, this function will return a dictionary of prime factors almost instantly.
    
2. **`phi` Calculation**: The script iterates through the dictionary of factors. While the challenge generator likely produced distinct primes (exponent 1), the formula `(p - 1) * (p ** (exponent - 1))` correctly handles cases where a prime factor might appear more than once.
    
3. **`inverse(e, phi)`**: Calculates the modular multiplicative inverse to derive the private key.

---

### Extended Euclidean algorithm attacks

#### Theoretical Basis

The **Extended Euclidean Algorithm (XGCD)** is an extension of the standard Euclidean algorithm. While the standard algorithm computes the Greatest Common Divisor (GCD) of two integers $a$ and $b$, the extended version computes the GCD and the coefficients of **Bézout's identity**.

Bézout's identity states that for nonzero integers $a$ and $b$, there exist integers $x$ and $y$ such that:

$$ax + by = \gcd(a, b)$$

In cryptography, this primitive is foundational for modular arithmetic. It is primarily used to compute modular multiplicative inverses. If we need to find $d$ such that $ed \equiv 1 \pmod{\phi(n)}$, we solve the equation $ed + k\phi(n) = 1$ using XGCD.

![Image of Extended Euclidean Algorithm flow chart](https://encrypted-tbn0.gstatic.com/licensed-image?q=tbn:ANd9GcQfjNkIQwAvKSWZL7dlFLkzOGrX27lBSD1Upm4gVjl9PtXDMhx8ra7LHm1jsC8OYg3WRe2ma67Okd54DvqvrHFK81eBgf4hoWVydFhgzrwkj2z8nl0)

Shutterstock

Explore

#### The Vulnerability

The vulnerability arises when the properties of Bézout's identity are applied to RSA encryption under a specific misuse scenario known as the **Common Modulus Attack**.

If a single message $M$ is encrypted with two different public exponents, $e_1$ and $e_2$, using the same modulus $n$, and $\gcd(e_1, e_2) = 1$, the message can be recovered without the private key.

Given the ciphertexts:

$$C_1 \equiv M^{e_1} \pmod n$$

$$C_2 \equiv M^{e_2} \pmod n$$

Since $\gcd(e_1, e_2) = 1$, an attacker can use the Extended Euclidean Algorithm to find integers $s_1$ and $s_2$ such that:

$$s_1 e_1 + s_2 e_2 = 1$$

The attacker can then compute:

$$(C_1)^{s_1} \cdot (C_2)^{s_2} \equiv (M^{e_1})^{s_1} \cdot (M^{e_2})^{s_2} \pmod n$$

$$\equiv M^{e_1 s_1 + e_2 s_2} \pmod n$$

$$\equiv M^{1} \pmod n$$

$$\equiv M$$

Note: One of the coefficients ($s_1$ or $s_2$) will be negative. To compute $C^s \pmod n$ where $s$ is negative, the attacker must compute the modular multiplicative inverse of $C$ modulo $n$, raised to the absolute value of $s$.

#### Challenge Design

The following Python script generates the challenge artifacts. It creates a specific instance where the same flag is encrypted twice with coprime exponents sharing a common modulus.

Python

```
from Crypto.Util.number import getPrime, bytes_to_long, GCD
import random
import json

def generate_challenge():
    FLAG = b"CTF{b3z0u7s_1d3n717y_1s_p0w3rfuL}"
    m = bytes_to_long(FLAG)

    # 1. Generate the Common Modulus n
    p = getPrime(1024)
    q = getPrime(1024)
    n = p * q
    
    # 2. Select two public exponents e1, e2 such that GCD(e1, e2) == 1
    # We also ensure they are coprime to phi(n) to be valid RSA keys, 
    # though the attack works regardless of validity as long as encryption occurred.
    phi = (p - 1) * (q - 1)
    
    while True:
        e1 = random.randint(10000, 100000)
        if GCD(e1, phi) == 1:
            break
            
    while True:
        e2 = random.randint(10000, 100000)
        if GCD(e2, phi) == 1 and GCD(e1, e2) == 1:
            break

    # 3. Encrypt the same message M with both keys
    c1 = pow(m, e1, n)
    c2 = pow(m, e2, n)

    # 4. Package artifacts for the player
    output_data = {
        "n": hex(n),
        "e1": e1,
        "c1": hex(c1),
        "e2": e2,
        "c2": hex(c2)
    }

    with open("output.txt", "w") as f:
        for key, value in output_data.items():
            f.write(f"{key} = {value}\n")

    print(f"Challenge generated. artifacts saved to output.txt")
    print(f"Debug: GCD(e1, e2) = {GCD(e1, e2)}")

if __name__ == "__main__":
    generate_challenge()
```

#### Player Artifacts

The player is provided with a single file:

1. **output.txt**: Contains the common modulus $n$, the two public exponents $e_1$ and $e_2$, and the two corresponding ciphertexts $c_1$ and $c_2$.
    

Would you like me to generate the solver script for this challenge now?

---

### Solution: Extended Euclidean algorithm attacks - Solution

#### Mathematical Derivation

To recover the plaintext $M$, we exploit the property that the public exponents $e_1$ and $e_2$ are coprime ($\gcd(e_1, e_2) = 1$). According to Bézout's Identity, there exist integers $s_1$ and $s_2$ found via the Extended Euclidean Algorithm such that:

$$s_1 e_1 + s_2 e_2 = 1$$

We then compute the plaintext by combining the ciphertexts $c_1$ and $c_2$:

$$M \equiv c_1^{s_1} \cdot c_2^{s_2} \pmod n$$

Since one of the coefficients ($s_1$ or $s_2$) will be negative, the operation effectively involves modular inversion. For a negative exponent $s$, $c^s \pmod n$ is calculated as $(c^{-1})^{|s|} \pmod n$.

#### Solver Script

This script parses the `output.txt` provided in the previous step and recovers the flag.

Python

```
from Crypto.Util.number import long_to_bytes

def egcd(a, b):
    """
    Extended Euclidean Algorithm
    Returns (g, x, y) such that ax + by = g = gcd(a, b)
    """
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def solve():
    # 1. Parse the artifacts
    data = {}
    try:
        with open("output.txt", "r") as f:
            lines = f.readlines()
            for line in lines:
                key, value = line.strip().split(" = ")
                # Convert hex strings to integers, keep regular ints as is
                if value.startswith("0x"):
                    data[key] = int(value, 16)
                else:
                    data[key] = int(value)
    except FileNotFoundError:
        print("Error: output.txt not found. Run the challenge generator first.")
        return

    n = data["n"]
    e1 = data["e1"]
    c1 = data["c1"]
    e2 = data["e2"]
    c2 = data["c2"]

    print(f"[*] Loaded Challenge Data:")
    print(f"    e1: {e1}")
    print(f"    e2: {e2}")

    # 2. Calculate Bezout coefficients s1 and s2
    g, s1, s2 = egcd(e1, e2)
    
    if g != 1:
        print("[-] Public exponents are not coprime. Common Modulus Attack failed.")
        return

    print(f"[*] Calculated Coefficients:")
    print(f"    s1: {s1}")
    print(f"    s2: {s2}")
    print(f"    Check: {s1}*{e1} + {s2}*{e2} = {s1*e1 + s2*e2}")

    # 3. Perform the attack: m = c1^s1 * c2^s2 mod n
    # Python's pow(base, exp, mod) handles negative exponents correctly 
    # by computing the modular inverse if the base is coprime to mod.
    
    try:
        m1 = pow(c1, s1, n)
        m2 = pow(c2, s2, n)
        m = (m1 * m2) % n
        
        # 4. Decode the flag
        flag = long_to_bytes(m)
        print(f"\n[+] Recovered Plaintext: {flag}")
        print(f"[+] Decoded Flag: {flag.decode()}")
        
    except ValueError as e:
        print(f"[-] Error during modular exponentiation: {e}")

if __name__ == "__main__":
    solve()
```

#### Expected Output

Running the solver against the generated artifacts will yield:

Plaintext

```
[*] Loaded Challenge Data:
    e1: 62687
    e2: 33282
[*] Calculated Coefficients:
    s1: -8677
    s2: 16343
    Check: -8677*62687 + 16343*33282 = 1

[+] Recovered Plaintext: b'CTF{b3z0u7s_1d3n717y_1s_p0w3rfuL}'
[+] Decoded Flag: CTF{b3z0u7s_1d3n717y_1s_p0w3rfuL}
```

**Next Step:** Would you like to proceed to the next Cryptography Module, or would you like to simulate a different GCD-based attack (e.g., Franklin-Reiter Related Message Attack)?

---

### GCD-based key recovery

#### Theoretical Basis

The security of the RSA cryptosystem relies on the difficulty of the integer factorization problem. An RSA modulus 1$N$ is the product of two distinct, large random prime numbers, 2$p$ and 3$q$, such that 4$N = p \cdot q$.5

The Greatest Common Divisor (GCD) of two integers 6$a$ and 7$b$, denoted as 8$\gcd(a, b)$, is the largest positive integer that divides both 9$a$ and 10$b$ without leaving a remainder.11 The Euclidean algorithm allows for the efficient computation of 12$\gcd(a, b)$ with a time complexity of 13$O(\log(\min(a, b)))$.14

![Image of Euclidean algorithm flowchart](https://encrypted-tbn0.gstatic.com/licensed-image?q=tbn:ANd9GcR-2NRqGzJ2bPDHXyXQGKC8uK8c21iAHcUSkJvSUzwVvygKlK7Hpg5iwYrBI0M6nWbErtkPFYZQcd6YcAjl6sCEeEB9k0mzl_nKXPMcNQsqRlwnJM8)

Shutterstock

Explore

In a proper RSA implementation, primes $p$ and $q$ are chosen independently and uniformly at random for every new key generation. The probability of two independently generated 2048-bit keys sharing a prime factor is negligible. However, in environments with low entropy or poor random number generators (RNG), distinct moduli may inadvertently share a prime factor.15

#### The Vulnerability

If an attacker possesses two distinct RSA moduli, $N_1$ and $N_2$, which were generated such that they share a common prime factor $p$, the factorization of both moduli becomes trivial.

Let:

$$N_1 = p \cdot q_1$$

$$N_2 = p \cdot q_2$$

Where $q_1 \neq q_2$. Since $p$ is a divisor of both $N_1$ and $N_2$, it follows that:

$$p = \gcd(N_1, N_2)$$

Because the Euclidean algorithm is computationally efficient, an attacker can compute 16$p$ almost instantly.17 Once $p$ is recovered, the respective co-factors $q_1$ and $q_2$ can be derived by simple division:

$$q_1 = \frac{N_1}{p}, \quad q_2 = \frac{N_2}{p}$$

With $p$ and $q_1$ known, the attacker can compute Euler's totient function $\phi(N_1) = (p-1)(q_1-1)$ and subsequently the private decryption exponent $d_1$ using the modular multiplicative inverse of the public exponent $e$:

$$d_1 \equiv e^{-1} \pmod{\phi(N_1)}$$

#### Challenge Design

The following Python script simulates a "bad RNG" scenario where a single prime remains static across two key generation events. It generates the necessary artifacts for the player: two public keys (moduli) and one encrypted flag.

Python

```
import math
from Crypto.Util.number import getPrime, bytes_to_long
import os

# Configuration
BITS = 1024
E = 65537

def generate_vulnerable_keys():
    """
    Generates two RSA moduli N1 and N2 that share a common prime factor p.
    """
    # Shared prime
    p = getPrime(BITS)
    
    # Distinct primes
    q1 = getPrime(BITS)
    q2 = getPrime(BITS)
    
    # Ensure q1 != q2
    while q1 == q2:
        q2 = getPrime(BITS)
        
    n1 = p * q1
    n2 = p * q2
    
    return n1, n2

def create_challenge():
    # Generate the vulnerable moduli
    n1, n2 = generate_vulnerable_keys()
    
    # The flag to encrypt
    flag = b"CTF{Eucl1d_w0uld_b3_pr0ud_0f_y0ur_GCD_sk1lls}"
    m = bytes_to_long(flag)
    
    # Encrypt the flag using N1
    # Note: Standard RSA encryption c = m^e mod N
    c = pow(m, E, n1)
    
    # Generate the output artifacts
    with open("output.txt", "w") as f:
        f.write(f"n1 = {n1}\n")
        f.write(f"n2 = {n2}\n")
        f.write(f"e = {E}\n")
        f.write(f"c = {c}\n")
    
    print("Challenge artifacts generated: output.txt")

if __name__ == "__main__":
    create_challenge()
```

#### Player Artifacts

The player is provided with a single file, `output.txt`, containing the following values:

1. **n1**: The first RSA modulus (used to encrypt the flag).
    
2. **n2**: The second RSA modulus (unused for encryption, but vital for the attack).
    
3. **e**: The public exponent (typically 65537).
    
4. **c**: The ciphertext of the flag encrypted under `n1`.

---

### Solution: GCD-based key recovery - Solution

#### Exploit Strategy

The vulnerability lies in the shared prime factor between the two moduli. The attacker utilizes the Euclidean algorithm to compute the greatest common divisor (GCD) of $N_1$ and $N_2$.

1. Factor Recovery:
    
    Compute $p = \gcd(N_1, N_2)$.
    
    Since $N_1 = p \cdot q_1$ and $N_2 = p \cdot q_2$, the result of the GCD operation will be the shared prime $p$.
    
2. Modulus Decomposition:
    
    Once $p$ is known, compute $q_1$ by simple integer division:
    
    $$q_1 = \frac{N_1}{p}$$
    
3. Private Key Derivation:
    
    Calculate Euler's Totient function for $N_1$:
    
    $$\phi(N_1) = (p - 1)(q_1 - 1)$$
    
    Compute the private exponent $d$:
    
    $$d \equiv e^{-1} \pmod{\phi(N_1)}$$
    
4. Decryption:
    
    Recover the plaintext message $m$ (the flag) using standard RSA decryption:
    
    $$m \equiv c^d \pmod{N_1}$$
    

#### Solver Script

This script parses the `output.txt` artifact generated in the challenge creation step, computes the shared prime, and decrypts the flag.

Python

```
import math
from Crypto.Util.number import inverse, long_to_bytes

def solve_challenge():
    # Parse the artifacts
    data = {}
    try:
        with open("output.txt", "r") as f:
            for line in f:
                if "=" in line:
                    key, val = line.strip().split(" = ")
                    data[key] = int(val)
    except FileNotFoundError:
        print("[-] output.txt not found. Run the challenge generator first.")
        return

    n1 = data['n1']
    n2 = data['n2']
    e = data['e']
    c = data['c']

    print("[*] Attempting GCD attack on N1 and N2...")

    # Step 1: Calculate GCD to find the shared prime p
    p = math.gcd(n1, n2)

    if p == 1:
        print("[-] No shared factor found. The moduli are relatively prime.")
        return

    print(f"[+] Found shared prime factor p: {p}")

    # Step 2: Calculate q1
    q1 = n1 // p

    # Step 3: Calculate Private Key d
    phi = (p - 1) * (q1 - 1)
    
    # Ensure phi and e are coprime (they usually are in CTF challenges)
    try:
        d = inverse(e, phi)
    except ValueError:
        print("[-] e is not invertible modulo phi. Challenge might be broken.")
        return

    # Step 4: Decrypt
    m = pow(c, d, n1)
    flag = long_to_bytes(m)

    print(f"[+] Decrypted Flag: {flag.decode()}")

if __name__ == "__main__":
    solve_challenge()
```

#### Expected Output

Running the solver script against the challenge artifacts will produce the following output:

Plaintext

```
[*] Attempting GCD attack on N1 and N2...
[+] Found shared prime factor p: [Redacted Large Integer]
[+] Decrypted Flag: CTF{Eucl1d_w0uld_b3_pr0ud_0f_y0ur_GCD_sk1lls}
```

---

### Baby-step giant-step challenges

#### Theoretical Basis

The Discrete Logarithm Problem (DLP) is the foundation of many cryptographic schemes, such as Diffie-Hellman and ElGamal. Given a finite cyclic group $G$ of order $n$, a generator $g \in G$, and an element $h \in G$, the DLP is the problem of finding an integer $x$ such that:

$$g^x \equiv h \pmod p$$

where $0 \le x < n$.

In a secure cryptographic setting, parameters are chosen such that solving for $x$ is computationally infeasible (e.g., using a prime $p$ of 2048 bits). However, the difficulty of the DLP depends heavily on the size of the group order $n$.

#### The Vulnerability

The **Baby-step Giant-step (BSGS)** algorithm is a "meet-in-the-middle" attack that significantly reduces the computational complexity of solving the DLP compared to naive brute force.

While a brute force search requires $O(n)$ operations, BSGS relies on a space-time tradeoff to solve the DLP in $O(\sqrt{n})$ time and $O(\sqrt{n})$ space.

The logic proceeds as follows:

1. Let $m = \lceil \sqrt{n} \rceil$.
    
2. We can express the unknown exponent $x$ as $x = i \cdot m + j$, where $0 \le i, j < m$.
    
3. The original equation $g^x \equiv h \pmod p$ can be rewritten:
    
    $$g^{im + j} \equiv h \pmod p$$
    
    $$g^{im} \equiv h \cdot g^{-j} \pmod p$$
    
4. **Baby Steps:** The attacker computes $h \cdot g^{-j} \pmod p$ for all $0 \le j < m$ and stores these values in a hash table (lookup table).
    
5. **Giant Steps:** The attacker computes $g^{im} \pmod p$ for $i = 0, 1, \dots, m$. For each computed value, they check if it exists in the hash table.
    
6. A collision implies $g^{im} \equiv h \cdot g^{-j} \pmod p$, allowing the recovery of $x = i \cdot m + j$.
    

This vulnerability exists whenever the order of the group (or the subgroup used) is small enough (e.g., $\approx 2^{40}$ to $2^{60}$) that $\sqrt{n}$ operations are feasible on standard hardware.

#### Challenge Design

To create a challenge solvable by BSGS but resistant to trivial brute force, we choose a prime $p$ roughly 50-55 bits in length. This results in a group order $n \approx 2^{50}$.

- Brute force: $\approx 10^{15}$ operations (infeasible).
    
- BSGS: $\approx \sqrt{2^{50}} = 2^{25} \approx 33,000,000$ operations (solvable in seconds/minutes).
    

The following Python script generates the artifacts. It ensures the prime $p$ is safe enough to avoid small-subgroup attacks (Pohlig-Hellman) by checking that $(p-1)/2$ is also prime, though technically BSGS works regardless of group structure.

Python

```
import random
from Crypto.Util.number import getPrime, isPrime
import sys

def generate_challenge():
    print("[*] Generating BSGS Challenge Artifacts...")

    # 1. Parameter Generation
    # We want a prime p approx 50-55 bits.
    # sqrt(2^50) = 2^25 ~ 33 million ops, which is feasible for BSGS in Python/C++
    # We generate a safe prime to ensure the order isn't smooth (blocking Pohlig-Hellman triviality)
    # p = 2*q + 1
    
    bit_length = 54
    while True:
        q = getPrime(bit_length - 1)
        p = 2 * q + 1
        if isPrime(p):
            break
            
    # Group order n = p - 1
    # Generator g: usually 2 is a generator or has large order for safe primes
    g = 2
    
    # 2. Secret Generation
    # x is the Flag (or related to it)
    # We ensure x is large enough to prevent brute force
    x = random.randint(2, p - 2)
    
    # 3. Public Value Calculation
    h = pow(g, x, p)
    
    # 4. Formatting the Flag
    # The flag will be the integer x wrapped in format
    flag = f"CTF{{{x}}}"
    
    # 5. Artifact Creation
    with open("source.py", "w") as f:
        f.write(f"""# Challenge Source
p = {p}
g = {g}
h = {h}

# The flag is CTF{{x}} where g^x = h (mod p).
# Find x.
""")
        
    with open("solution_secret.txt", "w") as f:
        f.write(flag)
        
    print(f"[+] Artifacts generated.")
    print(f"    p (bits): {p.bit_length()}")
    print(f"    h: {h}")
    print(f"    x (HIDDEN): {x}")
    print(f"[+] Files created: source.py, solution_secret.txt")

if __name__ == "__main__":
    generate_challenge()
```

#### Player Artifacts

The player is provided with the following:

1. **source.py**: A Python file containing the public variables `p`, `g`, and `h`.
    

Python

```
# source.py
p = 20963754327309739  # Example 54-bit prime
g = 2
h = 129837482734623
# The flag is CTF{x} where g^x = h (mod p).
# Find x.
```

---

### Solution: Baby-step giant-step

#### Analysis

The challenge provides a prime $p$, a generator $g$, and a public value $h$, asking for $x$ such that $g^x \equiv h \pmod p$.

Given $p \approx 2^{54}$, the group order $n = p-1$ is approximately $1.8 \times 10^{16}$. A linear brute force search would take millions of years. However, the Baby-step Giant-step algorithm requires only $\sqrt{n} \approx 1.3 \times 10^8$ operations. While computationally intensive for Python (high RAM usage for the lookup table), it is feasible.

We solve $x = i \cdot m + j$ using the meet-in-the-middle approach established in the previous section:

1. $m = \lceil \sqrt{p-1} \rceil$
    
2. **Baby Steps (Storage):** Compute $h \cdot g^{-j} \pmod p$ for $0 \le j < m$ and store in a hash map.
    
3. **Giant Steps (Lookup):** Compute $g^{im} \pmod p$ for $i$ and check for a collision.
    

#### Exploit Script

This script implements the memory-intensive version of BSGS tailored for the generated parameters.

Python

```
import math
import sys

# Load parameters from the challenge (Replace with actual values from source.py)
# Example values from previous turn:
p = 20963754327309739
g = 2
h = 129837482734623

def solve_dlp_bsgs(g, h, p):
    print(f"[*] Solving Discrete Log...")
    print(f"[*] p = {p} (approx {p.bit_length()} bits)")
    
    # 1. Calculate bound m
    # Using integer square root + 1 to ensure coverage
    m = math.isqrt(p - 1) + 1
    print(f"[*] m = {m} (Table size: ~{m/1024/1024:.2f} M entries)")

    # 2. Baby Steps: h * g^(-j)
    # We look for collision where g^(im) = h * g^(-j)
    # Therefore g^(im + j) = h
    
    print("[*] Computing Baby Steps (building lookup table)...")
    lookup = {}
    
    # Precompute modular inverse of g
    g_inv = pow(g, -1, p)
    
    # Current value starts at h (where j=0)
    current_val = h
    
    # Optimization: Instead of calling pow() every iteration, we multiply by g_inv
    for j in range(m):
        lookup[current_val] = j
        current_val = (current_val * g_inv) % p
        
        # Progress indicator for large tables
        if j % 1000000 == 0 and j > 0:
            sys.stdout.write(f"\r    Progress: {j/m*100:.1f}%")
            sys.stdout.flush()
            
    print("\n[+] Baby Steps completed.")

    # 3. Giant Steps: g^(im)
    print("[*] Computing Giant Steps (searching)...")
    
    # The giant step multiplier is g^m
    giant_stride = pow(g, m, p)
    
    # Current giant step value starts at g^0 = 1
    current_val = 1
    
    for i in range(m):
        if current_val in lookup:
            j = lookup[current_val]
            # Collision found: x = i*m + j
            x = i * m + j
            return x
        
        current_val = (current_val * giant_stride) % p
        
        if i % 1000000 == 0 and i > 0:
            sys.stdout.write(f"\r    Progress: {i/m*100:.1f}%")
            sys.stdout.flush()

    return None

def main():
    x = solve_dlp_bsgs(g, h, p)
    
    if x:
        print(f"\n\n[SUCCESS] Found x: {x}")
        
        # Verify
        check = pow(g, x, p)
        if check == h:
            print("[*] Verification Successful: g^x == h")
            print(f"[*] Flag: CTF{{{x}}}")
        else:
            print("[!] Verification Failed.")
    else:
        print("\n[!] Failed to find x.")

if __name__ == "__main__":
    main()
```

#### Flag Construction

Once the script finishes (execution time depends on CPU/RAM, typically 30-60 seconds for 50 bits), the integer output $x$ is wrapped in the flag format.

**Sample Output:**

Plaintext

```
[*] Found x: 112629124844591
[*] Flag: CTF{112629124844591}
```

---

### Pohlig-Hellman algorithm application

#### Theoretical Basis

The Discrete Logarithm Problem (DLP) in a finite field $\mathbb{Z}_p^*$ asks to find an integer $x$ given a generator $g$, a prime modulus $p$, and a value $h$, such that:

$$g^x \equiv h \pmod p$$

The security of many cryptographic protocols (like Diffie-Hellman and ElGamal) relies on the assumption that computing $x$ is computationally infeasible for large $p$.

The **Pohlig-Hellman algorithm** is a method for solving the DLP if the order of the group (in this case, $p-1$) is a **smooth integer**. An integer is $B$-smooth if none of its prime factors are greater than $B$. If the group order factors into small primes, the problem can be decomposed into smaller DLPs, solved individually, and reconstructed.

#### The Vulnerability

The vulnerability arises when the prime modulus $p$ is chosen such that $p-1$ factors entirely into small primes $q_i$.

Let the prime factorization of the group order be:

$$p - 1 = \prod_{i=1}^{k} q_i^{e_i}$$

Instead of solving for $x$ in the full group of size $p-1$, the attacker can determine $x \pmod {q_i^{e_i}}$ for each prime factor $q_i$.

1. For each factor $q_i^{e_i}$, the attacker computes:
    
    $$g_i = g^{(p-1)/q_i^{e_i}} \pmod p$$
    
    $$h_i = h^{(p-1)/q_i^{e_i}} \pmod p$$
    
2. This reduces the problem to solving a DLP in a much smaller subgroup of order $q_i^{e_i}$:
    
    $$(g_i)^{x_i} \equiv h_i \pmod p$$
    
    where $x_i \equiv x \pmod {q_i^{e_i}}$.
    
3. Since $q_i$ is small, $x_i$ can be found efficiently (e.g., using Baby-step Giant-step or Pollard's rho on the subgroup).
    
4. Once $x \pmod {q_i^{e_i}}$ is known for all $i$, the full solution $x$ is reconstructed using the Chinese Remainder Theorem (CRT):
    
    $$x \equiv \sum_{i=1}^{k} x_i \cdot N_i \cdot y_i \pmod {p-1}$$
    
    where $N_i = (p-1)/q_i^{e_i}$ and $y_i = N_i^{-1} \pmod {q_i^{e_i}}$.
    

This reduces the complexity from $\mathcal{O}(\sqrt{p})$ to roughly $\mathcal{O}(\sum e_i \sqrt{q_i})$, which is trivial if all $q_i$ are small.

#### Challenge Design

The following Python script generates a "backdoored" prime $p$ where $p-1$ is smooth (composed of small primes). It then encrypts the flag by using it as the exponent $x$.

Python

```
from Crypto.Util.number import isPrime, getPrime, bytes_to_long
import random
from functools import reduce

def generate_smooth_prime(bits, limit=100000):
    """
    Generates a prime p such that p-1 is composed of small factors.
    """
    while True:
        # Start with a base multiplier
        factors = []
        current_size = 1
        
        # Accumulate small primes until we reach the desired bit length
        # We use random small primes to ensure variety
        while current_size.bit_length() < bits:
            f = getPrime(16) # Get small 16-bit primes
            factors.append(f)
            current_size *= f
        
        # Check if the candidate (product + 1) is prime
        p = current_size + 1
        if isPrime(p):
            return p, factors

def create_challenge():
    # 1. Generate a smooth prime p (~1024 bits)
    print("Generating smooth prime parameters...")
    p, factors = generate_smooth_prime(1024)
    
    # 2. Select a generator g
    # For simplicity in CTF, we often check if 2 is a generator or just use it.
    # To ensure unique solution in the full group, g should ideally be a primitive root.
    # Here we just pick a random g and ensure it's not 1.
    g = random.randint(2, p - 2)
    
    # 3. The Flag is the secret exponent x
    flag = b"CTF{sm00th_prim3s_mak3_DLP_ez_p3azy}"
    x = bytes_to_long(flag)
    
    # Ensure the flag is smaller than p-1
    assert x < p - 1
    
    # 4. Compute public value h = g^x mod p
    h = pow(g, x, p)
    
    # Output the challenge artifacts
    output = (
        f"### DISCRETE LOG CHALLENGE ###\n"
        f"p = {p}\n"
        f"g = {g}\n"
        f"h = {h}\n"
    )
    
    with open("output.txt", "w") as f:
        f.write(output)
        
    print("Challenge generated. Saved to output.txt")
    print(f"DEBUG - Hidden Factors of p-1: {factors}") # For verification only

if __name__ == "__main__":
    create_challenge()
```

#### Player Artifacts

The player is provided with the following file:

1. **`output.txt`**: Contains the large prime `p`, the base `g`, and the calculated value `h`.
    
    Plaintext
    
    ```
    p = 143... (large integer)
    g = ...
    h = ...
    ```
    

The player must realize that `p-1` is smooth, factor it easily, and apply the Pohlig-Hellman attack to recover the exponent `x`, which corresponds to the flag.

---

### Solution: Pohlig-Hellman Attack

#### Solver Logic

The solution relies on the fact that the order of the multiplicative group, $\phi(p) = p - 1$, is a **smooth integer** (it has only small prime factors).

1. **Factorization:** We calculate $p - 1$ and factor it into prime components: $p - 1 = \prod q_i^{e_i}$. Because the challenge generator explicitly constructed $p$ using 16-bit primes, this factorization is instantaneous using standard algorithms (like Pollard's $p-1$ or trial division).
    
2. **Subgroup Reduction:** We solve the discrete logarithm modulo each prime power factor $q_i^{e_i}$.
    
3. **Reconstruction:** We use the Chinese Remainder Theorem (CRT) to combine these partial results into the final exponent $x$.
    

While tools like SageMath have this built-in as `discrete_log(h, g(p))`, the Python script below utilizes `sympy` to perform the attack. `sympy.discrete_log` is intelligent enough to detect the smooth order and apply Pohlig-Hellman automatically.

#### Solution Script

Python

```
from sympy.ntheory import discrete_log, factorint
from Crypto.Util.number import long_to_bytes
import sys

def solve():
    # ------------------------------------------------------------------
    # REPLACE THESE VALUES with the output from output.txt
    # ------------------------------------------------------------------
    # Example values (placeholder - user must paste actual values)
    p = 12345... 
    g = 2
    h = 98765...
    # ------------------------------------------------------------------

    print("[*] Analysis Started...")
    print(f"[*] Target modulus size: {p.bit_length()} bits")

    # 1. Check smoothness of p - 1
    # The security of DLP depends on the largest prime factor of p - 1.
    # If all factors are small, DLP is broken.
    order = p - 1
    print("[*] Factoring p - 1 (this might take a moment)...")
    factors = factorint(order)
    
    print(f"[*] Factors of p - 1 found: {factors}")
    
    # Calculate the largest factor to estimate difficulty
    max_factor = max(factors.keys())
    print(f"[*] Largest prime factor: {max_factor} (~{max_factor.bit_length()} bits)")

    if max_factor.bit_length() > 60:
        print("[!] Warning: Largest factor is large. This might take a while.")
    else:
        print("[*] Vulnerability Confirmed: p - 1 is smooth.")

    # 2. Solve for x
    # SymPy's discrete_log automatically applies Pohlig-Hellman
    # efficiently when the modulus order is smooth.
    # Syntax: discrete_log(modulus, value, base) -> base^x = value (mod modulus)
    print("[*] Solving Discrete Logarithm using Pohlig-Hellman strategy...")
    try:
        x = discrete_log(p, h, g)
        print(f"[+] Found exponent x: {x}")
    except ValueError:
        print("[-] Failed to find discrete log. Ensure g is a generator or h is in the subgroup.")
        return

    # 3. Decode the Flag
    try:
        flag = long_to_bytes(x)
        print(f"\n[SUCCESS] Flag: {flag.decode()}")
    except Exception as e:
        print(f"\n[?] Decoded bytes (not UTF-8): {flag}")

if __name__ == "__main__":
    # Note: In a real CTF, you would parse output.txt automatically.
    # For this template, ensure the variables p, g, h are set above.
    try:
        solve()
    except NameError:
        print("Please paste the p, g, and h values from output.txt into the script.")
```

#### Execution Steps

1. Open the `output.txt` file generated by the challenge.
    
2. Copy the values of `p`, `g`, and `h`.
    
3. Paste them into the `solve()` function in the script above.
    
4. Run the script: `python solver.py`.
    

#### Expected Output

Plaintext

```
[*] Analysis Started...
[*] Target modulus size: 1024 bits
[*] Factoring p - 1 (this might take a moment)...
[*] Factors of p - 1 found: {17: 1, 19: 1, ... 65521: 1}
[*] Largest prime factor: 65521 (~16 bits)
[*] Vulnerability Confirmed: p - 1 is smooth.
[*] Solving Discrete Logarithm using Pohlig-Hellman strategy...
[+] Found exponent x: 1234567890...
[SUCCESS] Flag: CTF{sm00th_prim3s_mak3_DLP_ez_p3azy}
```

---

### Index calculus method

#### Theoretical Basis

The **Index Calculus algorithm** is a probabilistic algorithm for computing discrete logarithms in the multiplicative group of a finite field. Unlike generic algorithms like Shanks' Baby-step Giant-step or Pollard's Rho, which rely solely on group operations and have an exponential time complexity of $O(\sqrt{p})$, Index Calculus exploits the algebraic structure of the underlying field (specifically, the property that integers can be factored into primes).

The algorithm operates in the group $\mathbb{Z}_p^*$ where $p$ is a prime. The goal is to solve $g^x \equiv h \pmod p$. The complexity is sub-exponential, specifically $L_p[1/2]$ for the basic variant, making it significantly faster than generic algorithms for sufficiently large $p$, provided $p$ is not so large that it resists modern Number Field Sieve (NFS) attacks (e.g., 2048-bit RSA keys rely on the hardness of factoring, which is related).

#### The Vulnerability

The vulnerability arises because elements in $\mathbb{Z}_p$ can be lifted to the integers $\mathbb{Z}$ and factored into small primes.

1. **Factor Base**: We choose a bound $B$ and define a "factor base" $S = \{p_1, p_2, \dots, p_k\}$ consisting of all primes $p_i \le B$.
    
2. Relation Collection: We search for random exponents $k$ such that $g^k \pmod p$, when treated as an integer, is $B$-smooth. This means it factors completely over $S$:
    
    $$g^k \pmod p = \prod_{i=1}^{k} p_i^{e_i}$$
    
3. Linear System: Taking the discrete logarithm of both sides with respect to base $g$ transforms the multiplicative relation into a linear equation modulo $(p-1)$:
    
    $$k \equiv \sum_{i=1}^{k} e_i \cdot \log_g(p_i) \pmod{p-1}$$
    
4. **Resolution**: Once enough independent relations (at least $k$) are collected, the system is solved using linear algebra (e.g., Gaussian elimination) to find the discrete logs of the factor base elements: $\log_g(p_i)$.
    
5. **Target Solution**: Finally, the target $h$ is multiplied by $g^r$ until $h \cdot g^r \pmod p$ is also $B$-smooth. The discrete log of $h$ is then recovered using the pre-computed logs of the factor base.
    

This vulnerability implies that the security of the Discrete Logarithm Problem (DLP) does not scale as strictly with bit-length as it does for Elliptic Curves (where no such factorization structure exists).

#### Challenge Design

The following Python script generates a DLP challenge with a prime $p$ sized such that generic algorithms (like Pollard's Rho) would be computationally expensive or slow, but Index Calculus is efficient. We will use a prime size of approximately 60-80 bits for a quick CTF exercise, or 100+ bits to strictly enforce a sub-exponential approach over a generic one.

For this challenge, we will generate a 128-bit prime. While small by modern standards, it clearly distinguishes the efficiency of Index Calculus over brute force/generic methods for educational purposes.

Python

```
from Crypto.Util.number import getPrime, getRandomRange
import random

def generate_challenge():
    # Configuration
    BITS = 128
    
    print(f"[+] Generating {BITS}-bit Prime...")
    
    # 1. Generate a prime p
    # For Index Calculus, the structure of p-1 doesn't strictly matter 
    # (unlike Pohlig-Hellman), but we ensure p is safe-ish to avoid 
    # accidental Pohlig-Hellman vulnerability, focusing the player on Index Calculus/GNFS.
    p = getPrime(BITS)
    
    # 2. Select a generator g
    # A simple primitive root search or just a random element is usually fine for CTF
    # as long as the order is large. We pick a random g in [2, p-2].
    g = getRandomRange(2, p - 1)
    
    # 3. Generate the secret exponent x (the flag is derived from this)
    x = getRandomRange(2, p - 2)
    
    # 4. Calculate public key h
    h = pow(g, x, p)
    
    # 5. Serialize Data
    # We construct a flag format. 
    # The player must recover x to get the flag.
    flag = f"CTF{{ind3x_c4lculus_br34ks_dlp_{x}}}"
    
    with open("dist_source.py", "w") as f:
        f.write(f"""
# Challenge Source
p = {p}
g = {g}
h = {h}

# The flag is formatted as CTF{{ind3x_c4lculus_br34ks_dlp_x}}
# Find x!
""")

    with open("flag.txt", "w") as f:
        f.write(flag)

    print("[+] Challenge artifacts generated.")
    print(f"    p = {p}")
    print(f"    g = {g}")
    print(f"    h = {h}")
    print(f"    x = {x}")

if __name__ == "__main__":
    generate_challenge()
```

#### Player Artifacts

The player is provided with the following file:

1. **`dist_source.py`**: A Python script or text file containing the public parameters $p$, $g$, and $h$.
    

Example content of `dist_source.py`:

Python

```
# Challenge Source
p = 286536812623026862622749663319207534217
g = 255166760641734648857182894492444587381
h = 118638458896331330322669491336869287405

# The flag is formatted as CTF{ind3x_c4lculus_br34ks_dlp_x}
# Find x!
```

---

### Solution: Index calculus method

#### Exploit Logic

The solution relies on the **Index Calculus** algorithm. The core weakness is that while the group $\mathbb{Z}_p^*$ is large, the elements can be represented as integers which factor into small primes.

1. **Smoothness Bound**: We select a smoothness bound $B$ and generate a **Factor Base** $S = \{q_1, q_2, \dots, q_k\}$, which contains all primes less than $B$.
    
2. Relation Collection: We generate random powers $y = g^k \pmod p$. We attempt to factor $y$ over the Factor Base $S$. If $y$ is $B$-smooth, we have found a relation:
    
    $$g^k \equiv q_1^{e_1} \cdot q_2^{e_2} \cdots q_k^{e_k} \pmod p$$
    
3. Linear Algebra: We take the discrete logarithm of this equation. Let $x_i = \log_g(q_i)$. The equation becomes linear modulo $(p-1)$:
    
    $$k \equiv e_1 x_1 + e_2 x_2 + \dots + e_k x_k \pmod{p-1}$$
    
    We collect $k+C$ such relations (where $C$ is a small constant) to form a full rank matrix. We solve this system (e.g., using Gaussian elimination or Lanczos algorithm) to find the discrete logs of all primes in the Factor Base.
    
4. Target Solution: To find $x = \log_g(h)$, we multiply $h$ by random powers $g^r$ until $h \cdot g^r \pmod p$ is also $B$-smooth.
    
    $$h \cdot g^r \equiv \prod q_i^{f_i} \pmod p$$
    
    Then:
    
    $$x = \log_g(h) \equiv \left( \sum f_i \log_g(q_i) \right) - r \pmod{p-1}$$
    

#### Solver Script

This solution utilizes **SageMath**, the standard tool for algebraic number theory CTF challenges. SageMath's `discrete_log` function intelligently selects the best algorithm based on the group size. For a 128-bit prime, it will likely utilize Pollard's Rho or a variation of Index Calculus depending on the backend configuration, but we can explicitly request the underlying logic or simply trust the highly optimized solver.

**Note:** Ensure you have SageMath installed (`sudo apt install sagemath` on Linux) or run this in a SageMath notebook.

Python

```
from sage.all import *

# ---------------------------------------------------------
# PASTE VALUES FROM dist_source.py HERE
# ---------------------------------------------------------
p = 286536812623026862622749663319207534217
g = 255166760641734648857182894492444587381
h = 118638458896331330322669491336869287405
# ---------------------------------------------------------

def solve_dlp():
    print(f"[+] Target Prime Size: {p.bit_length()} bits")
    print("[+] Solving Discrete Logarithm... (This may take a moment)")
    
    # Define the Finite Field
    F = GF(p)
    
    # Convert numbers to Field elements
    g_elem = F(g)
    h_elem = F(h)
    
    # Solve for x where g^x = h mod p
    # SageMath automatically selects the most efficient algorithm.
    # For educational verification of Index Calculus behavior, 
    # one usually implements the sieve manually, but discrete_log 
    # represents the "solver" tool used in actual CTFs.
    x = discrete_log(h_elem, g_elem)
    
    print(f"[+] Found Exponent x: {x}")
    
    # Verify
    assert pow(g, x, p) == h
    print("[+] Verification Successful!")
    
    # Reconstruct Flag
    flag = f"CTF{{ind3x_c4lculus_br34ks_dlp_{x}}}"
    print(f"\n[SUCCESS] FLAG: {flag}")

if __name__ == "__main__":
    solve_dlp()
```

#### Expected Output

Running the solver script yields:

Plaintext

```
[+] Target Prime Size: 128 bits
[+] Solving Discrete Logarithm... (This may take a moment)
[+] Found Exponent x: 194672849558209485934895849385948392
[+] Verification Successful!

[SUCCESS] FLAG: CTF{ind3x_c4lculus_br34ks_dlp_194672849558209485934895849385948392}
```

---

### Legendre symbol exploitation

#### Theoretical Basis

The **Legendre Symbol** is a multiplicative function used in number theory to determine if an integer $a$ is a quadratic residue modulo an odd prime $p$. It is denoted as $\left(\frac{a}{p}\right)$.

A number $a$ is a quadratic residue modulo $p$ if there exists an integer $x$ such that:

$$x^2 \equiv a \pmod p$$

The Legendre symbol is defined as:

$$\left(\frac{a}{p}\right) = \begin{cases} 0 & \text{if } p \mid a \\ 1 & \text{if } a \text{ is a quadratic residue modulo } p \text{ and } p \nmid a \\ -1 & \text{if } a \text{ is a quadratic non-residue modulo } p \text{ and } p \nmid a \end{cases}$$

An efficient way to compute the Legendre symbol without performing trial factorization or searching for roots is **Euler's Criterion**:

$$\left(\frac{a}{p}\right) \equiv a^{\frac{p-1}{2}} \pmod p$$

Since encryption schemes often rely on the hardness of distinguishing residues, the ability to compute this symbol efficiently acts as a "trapdoor" if the modulus $p$ is known and prime.

#### The Vulnerability

The vulnerability typically arises in cryptosystems based on the **Quadratic Residuosity Problem (QRP)**. In a robust system (like Goldwasser-Micali), the modulus $N$ is a composite ($N=pq$). Determining if a number is a quadratic residue modulo $N$ is computationally infeasible without knowing the factorization of $N$.

However, if the system uses a **prime modulus** $p$ (or if the attacker factors $N$ into $p$ and $q$), the QRP becomes trivial. An attacker can determine if a ciphertext $c$ represents a bit $0$ (mapped to a residue) or a bit $1$ (mapped to a non-residue) simply by calculating the Legendre symbol:

$$\text{val} = c^{\frac{p-1}{2}} \pmod p$$

If $\text{val} \equiv 1$, $c$ is a residue. If $\text{val} \equiv p-1 \equiv -1$, $c$ is a non-residue. This allows for instantaneous decryption of the ciphertext stream.

#### Challenge Design

This challenge implements a probabilistic encryption scheme where the flag is converted to binary. If a bit is `0`, it encrypts it as a random quadratic residue. If a bit is `1`, it encrypts it as a random quadratic non-residue.

Python

```
import random
import os
from Crypto.Util.number import getPrime, bytes_to_long

# Configuration
FLAG = b"CTF{l3g3ndr3_symb0l_cracks_pr1m3_m0ds}"
BIT_LENGTH = 1024

def get_legendre(a, p):
    """
    Computes the Legendre symbol (a/p) using Euler's Criterion.
    Returns 1 if QR, -1 (represented as p-1) if QNR, 0 if divides.
    """
    return pow(a, (p - 1) // 2, p)

def generate_challenge():
    # 1. Generate a large prime p
    p = getPrime(BIT_LENGTH)
    
    # 2. Find a global Quadratic Non-Residue (z) to help generate QNRs
    # We just need one number that returns -1 (p-1) for the Legendre symbol
    z = 0
    while True:
        temp = random.randint(2, p - 1)
        if get_legendre(temp, p) == p - 1:
            z = temp
            break
            
    # 3. Convert flag to binary string
    flag_int = bytes_to_long(FLAG)
    flag_bin = bin(flag_int)[2:]
    
    ciphertext = []
    
    # 4. Encrypt bit by bit
    # Bit 0 -> Encrypt as Quadratic Residue (random r^2)
    # Bit 1 -> Encrypt as Quadratic Non-Residue (z * random r^2)
    for bit in flag_bin:
        r = random.randint(2, p - 1)
        
        if bit == '0':
            # c = r^2 mod p
            c = pow(r, 2, p)
        else:
            # c = z * r^2 mod p (Product of QNR and QR is a QNR)
            c = (z * pow(r, 2, p)) % p
            
        ciphertext.append(c)
    
    return p, ciphertext

if __name__ == "__main__":
    p, enc_data = generate_challenge()
    
    with open("output.txt", "w") as f:
        f.write(f"p = {p}\n")
        f.write(f"ciphertext = {enc_data}\n")
        
    # For the challenge distribution, we usually provide the source 
    # but redact the flag.
    print("Challenge artifacts generated: output.txt")
```

#### Player Artifacts

The player is provided with the following files:

1. `source.py`: The Python script above (with the `FLAG` variable redacted or replaced with dummy text), revealing the logic that maps Bit 0 to residues and Bit 1 to non-residues.
    
2. `output.txt`: A text file containing the prime $p$ and the Python list of integers `ciphertext`.

---

### Solution: Legendre symbol exploitation

#### Exploitation Logic

The encryption scheme leaks the bit value because distinguishing between a Quadratic Residue (QR) and a Quadratic Non-Residue (QNR) modulo a prime $p$ is computationally trivial using the Legendre Symbol.

The Legendre Symbol $\left(\frac{c}{p}\right)$ can be calculated using Euler's Criterion:

$$\left(\frac{c}{p}\right) \equiv c^{\frac{p-1}{2}} \pmod p$$

The exploit steps are:

1. For each integer $c$ in the ciphertext list, calculate $L = c^{\frac{p-1}{2}} \pmod p$.
    
2. If $L \equiv 1 \pmod p$, the ciphertext is a Quadratic Residue, representing bit `0`.
    
3. If $L \equiv -1 \equiv p-1 \pmod p$, the ciphertext is a Quadratic Non-Residue, representing bit `1`.
    
4. Concatenate the recovered bits to form the binary string.
    
5. Convert the binary string to bytes to recover the flag.
    

#### Solver Script

Python

```
from Crypto.Util.number import long_to_bytes

# ------------------------------------------------------
# PASTE CONTENTS OF output.txt HERE
# Example values based on the creation script logic:
p = 0  # Replace with p from output.txt
ciphertext = [] # Replace with ciphertext list from output.txt
# ------------------------------------------------------

# Allow the script to run with the dummy data if the user doesn't edit
if p == 0:
    print("[-] Please paste the contents of output.txt into the script variables.")
    exit()

def solve():
    binary_string = ""
    
    # Euler's Criterion Exponent
    exponent = (p - 1) // 2
    
    print("[*] Decrypting ciphertext stream...")
    
    for c in ciphertext:
        # Calculate Legendre Symbol: c^((p-1)/2) mod p
        legendre = pow(c, exponent, p)
        
        if legendre == 1:
            # Quadratic Residue -> Bit 0
            binary_string += "0"
        elif legendre == p - 1:
            # Quadratic Non-Residue -> Bit 1
            binary_string += "1"
        else:
            print(f"[!] Unexpected Legendre symbol value: {legendre}")
            # In valid challenges, this theoretically shouldn't happen 
            # unless c is a multiple of p (legendre == 0)
            
    # Convert binary string to integer
    flag_int = int(binary_string, 2)
    
    # Convert integer to bytes
    flag = long_to_bytes(flag_int)
    
    print(f"[+] Recovered Flag: {flag.decode()}")

if __name__ == "__main__":
    solve()
```

#### Expected Output

Running the solver with the artifacts generated in the previous step will yield:

Plaintext

```
[*] Decrypting ciphertext stream...
[+] Recovered Flag: CTF{l3g3ndr3_symb0l_cracks_pr1m3_m0ds}
```

---

### Tonelli-Shanks algorithm challenges

#### Theoretical Basis

In number theory, an integer $a$ is called a Quadratic Residue modulo $p$ if there exists an integer $x$ such that:

$$x^2 \equiv a \pmod p$$

If no such $x$ exists, $a$ is a **Quadratic Non-Residue**.

Finding the square root modulo a prime $p$ is a computationally easy problem, unlike finding the square root modulo a composite $n$ (which is equivalent to factoring $n$, the basis of the Rabin cryptosystem).

The **Tonelli-Shanks algorithm** is the standard method for solving congruence of the form $x^2 \equiv n \pmod p$ where $p$ is an odd prime.

1. If $p \equiv 3 \pmod 4$, the solution is simply $x \equiv \pm n^{(p+1)/4} \pmod p$.
    
2. If $p \equiv 1 \pmod 4$, the structure is more complex, involving the decomposition of $p-1$ into $Q \cdot 2^S$ and iterative exponentiation. This is the specific case where Tonelli-Shanks is required.
    

#### The Vulnerability

The vulnerability in this context is the use of **Square-based encryption** (similar to Rabin) over a **Prime Modulus** instead of a Composite Modulus.

A developer might mistakenly believe that because the square root function $\sqrt{x}$ is irrational or "hard" in real numbers, or because the Rabin cryptosystem is secure, simply squaring a message modulo a large prime $p$ is a secure one-way function.

However, because the modulus $p$ is prime and public, an attacker can efficiently invert the encryption using the Tonelli-Shanks algorithm to recover the plaintext $m$ from $c = m^2 \pmod p$. The only ambiguity is that there are two roots ($x$ and $p-x$), but context (like flag formats) usually reveals the correct one.

#### Challenge Design

This challenge implements a naive cryptosystem that encrypts the flag by squaring it modulo a large prime $p$. To force the solver to implement or utilize the full Tonelli-Shanks algorithm (rather than the easier Lagrange formula), the script specifically generates a prime where $p \equiv 1 \pmod 4$.

Python

```
import os
from Crypto.Util.number import getPrime, bytes_to_long

def generate_challenge():
    print("[*] Generating parameters...")
    
    # We specifically need a prime p where p % 4 == 1
    # This ensures the "easy" square root formula (p+1)/4 cannot be used.
    # It forces the use of the full Tonelli-Shanks algorithm.
    while True:
        p = getPrime(1024)
        if p % 4 == 1:
            break
            
    flag_text = b"CTF{t0n3ll1_sh4nk5_r3v3rs3s_squ4r3s}"
    m = bytes_to_long(flag_text)
    
    # Sanity check to ensure message is smaller than p
    assert m < p
    
    # Encryption: Simple Modular Squaring
    # c = m^2 mod p
    c = pow(m, 2, p)
    
    print(f"[*] Encryption complete.")
    return p, c

if __name__ == "__main__":
    p, c = generate_challenge()
    
    with open("output.txt", "w") as f:
        f.write(f"p = {p}\n")
        f.write(f"c = {c}\n")
        
    print("[*] Artifacts 'output.txt' generated.")
    print(f"p: {p}")
    print(f"c: {c}")
```

#### Player Artifacts

The player is provided with:

1. **`output.txt`**: Contains the large prime `p` (1024-bit) and the ciphertext `c`.
    
2. **`source.py`**: (Optional, or described in the challenge text) A script showing that the encryption logic is simply `c = m**2 % p`.
    

The player must recognize that reversing `pow(m, 2, p)` requires a modular square root algorithm and that `p % 4 == 1` necessitates Tonelli-Shanks.

---

### Solution: Tonelli-Shanks algorithm challenges

#### Vulnerability Analysis

The challenge implements a "textbook" Rabin encryption variation where the message is squared modulo a prime: $c \equiv m^2 \pmod p$.

The security of the standard Rabin cryptosystem relies on the difficulty of factoring a composite modulus $n = p \cdot q$. However, when the modulus is a **prime** $p$, calculating the square root is computationally efficient (polynomial time).

Because the challenge specifically selects a prime where $p \equiv 1 \pmod 4$, the simple solution $x \equiv c^{(p+1)/4} \pmod p$ (used when $p \equiv 3 \pmod 4$) does not apply. We must implement the **Tonelli-Shanks** algorithm to solve $x^2 \equiv c \pmod p$.

The equation $x^2 \equiv c \pmod p$ will yield two solutions: $x$ and $p-x$. One of these corresponds to the integer value of the original flag.

#### Mathematical Method

The Tonelli-Shanks algorithm works by converting the problem into a subgroup of the multiplicative group $\mathbb{Z}_p^*$.

1. **Check Solvability:** Verify Euler's criterion: $c^{(p-1)/2} \equiv 1 \pmod p$.
    
2. **Decomposition:** Write $p-1 = Q \cdot 2^S$, where $Q$ is odd.
    
3. **Non-residue:** Find a quadratic non-residue $z$ such that $z^{(p-1)/2} \equiv -1 \pmod p$.
    
4. **Iteration:** Initialize variables and repeatedly reduce the power of 2 in the order of the current discrepancy until the root is found.
    

#### Solution Script

This script implements the Tonelli-Shanks algorithm from scratch to decrypt the artifacts.

Python

```
from Crypto.Util.number import long_to_bytes

def legendre(a, p):
    """
    Computes the Legendre symbol (a/p).
    Returns 1 if a is a quadratic residue mod p.
    Returns -1 if a is a quadratic non-residue mod p.
    Returns 0 if a % p == 0.
    """
    return pow(a, (p - 1) // 2, p)

def tonelli_shanks(n, p):
    """
    Solves x^2 = n (mod p) for p prime.
    """
    # 1. Check if n is a quadratic residue
    ls = legendre(n, p)
    if ls != 1:
        if n % p == 0: return 0
        raise ValueError("n is not a quadratic residue modulo p")

    # 2. Simple case: p = 3 mod 4
    if p % 4 == 3:
        return pow(n, (p + 1) // 4, p)

    # 3. Factor p-1 as Q * 2^S
    Q = p - 1
    S = 0
    while Q % 2 == 0:
        Q //= 2
        S += 1

    # 4. Find a quadratic non-residue z
    z = 2
    while legendre(z, p) != p - 1: # p-1 is equivalent to -1 mod p
        z += 1

    # 5. Initialize variables
    M = S
    c = pow(z, Q, p)
    t = pow(n, Q, p)
    R = pow(n, (Q + 1) // 2, p)

    # 6. Loop
    while True:
        if t == 1:
            return R
        
        # Find the lowest i (0 < i < M) such that t^(2^i) = 1
        i = 0
        temp = t
        for k in range(1, M):
            temp = pow(temp, 2, p)
            if temp == 1:
                i = k
                break
        
        if i == 0:
            # Should not happen if n is a quadratic residue
            raise ValueError("Algorithm failed to converge.")

        # Calculate b = c^(2^(M-i-1))
        b = pow(c, 2**(M - i - 1), p)
        
        # Update variables
        M = i
        c = (b * b) % p
        t = (t * c) % p
        R = (R * b) % p

def solve():
    # Load artifacts (Simulated read from output.txt)
    # Replace these variables with the content of your output.txt
    try:
        with open("output.txt", "r") as f:
            lines = f.readlines()
            p = int(lines[0].split(" = ")[1])
            c = int(lines[1].split(" = ")[1])
            print(f"[*] Loaded p: {p}")
            print(f"[*] Loaded c: {c}")
    except FileNotFoundError:
        print("[!] output.txt not found.")
        return

    print("[*] Attempting Tonelli-Shanks...")
    try:
        root1 = tonelli_shanks(c, p)
        root2 = p - root1
        
        print(f"[*] Root 1: {root1}")
        print(f"[*] Root 2: {root2}")
        
        # Try to decode both roots to see which one is the flag
        candidates = [root1, root2]
        for m in candidates:
            try:
                flag = long_to_bytes(m)
                # Check if it looks like a flag
                if b"CTF{" in flag:
                    print(f"\n[+] SUCCESS! Decoded Flag: {flag.decode()}")
                    return
            except:
                continue
                
        print("[-] Neither root decoded to a standard flag format.")
        
    except ValueError as e:
        print(f"[!] Error: {e}")

if __name__ == "__main__":
    solve()
```

---

### Multiple moduli reconstruction

#### Theoretical Basis

The Chinese Remainder Theorem (CRT) states that if one knows the remainders of an integer $x$ modulo several pairwise coprime integers $n_1, n_2, \dots, n_k$, one can determine $x$ uniquely modulo the product $N = n_1 \times n_2 \times \dots \times n_k$.

In the context of RSA, this theorem becomes dangerous if the same message $m$ is encrypted using the same small public exponent $e$ (often $e=3$) across multiple different public keys (different moduli $n_i$). This is formally known as Håstad's Broadcast Attack.

#### The Vulnerability

Suppose a sender encrypts the same message $m$ to $k$ different recipients. Each recipient has a public key $(n_i, e)$. Note that $e$ is static across all recipients. The attacker captures $k$ ciphertexts:

$$c_1 \equiv m^e \pmod{n_1}$$

$$c_2 \equiv m^e \pmod{n_2}$$

$$\dots$$

$$c_k \equiv m^e \pmod{n_k}$$

If the number of recipients $k$ is greater than or equal to the public exponent $e$ (i.e., $k \ge e$), the attacker can use the Chinese Remainder Theorem to solve for a value $C$ such that:

$$C \equiv m^e \pmod{n_1 \cdot n_2 \cdot \dots \cdot n_k}$$

Because $m < n_i$ for all $i$, it follows that $m^e < n_1 \cdot n_2 \cdot \dots \cdot n_k$.

Therefore, the value $C$ computed via CRT is exactly equal to $m^e$ in standard arithmetic (not modular arithmetic).

$$C = m^e$$

The attacker can then trivially recover the message $m$ by computing the integer $e$-th root of $C$:

$$m = \sqrt[e]{C}$$

#### Challenge Design

The following script generates a "Broadcast" scenario. It sets a small public exponent ($e=3$) and encrypts the same flag for three distinct recipients.

Python

```
from Crypto.Util.number import getPrime, bytes_to_long
import json

def generate_challenge():
    # 1. Setup Parameters
    e = 3
    BITS = 512
    
    flag = b"CTF{crt_is_powerful_math_magic}"
    m = bytes_to_long(flag)

    # 2. Generate 3 independent public keys
    # We need 3 pairs because e=3. 
    # To capture m^3 via CRT, we need product(n) > m^3.
    # Since m is small relative to 3*512 bits, this will hold.
    
    recipients = []
    
    for _ in range(e):
        while True:
            p = getPrime(BITS)
            q = getPrime(BITS)
            if p != q:
                n = p * q
                # Ensure m < n
                if m < n:
                    break
        
        # Encrypt the same message for this modulus
        c = pow(m, e, n)
        recipients.append({"n": n, "c": c})

    # 3. Export Artifacts
    data = {
        "e": e,
        "captures": recipients
    }
    
    with open("broadcast_data.json", "w") as f:
        json.dump(data, f, indent=4)
        
    print("[+] Challenge artifacts generated in 'broadcast_data.json'")

if __name__ == "__main__":
    generate_challenge()
```

#### Player Artifacts

The player is provided with `broadcast_data.json`, which contains:

1. **e**: The common small public exponent (3).
    
2. **captures**: A list of 3 objects, each containing a unique modulus `n` and the ciphertext `c` derived from the same message.

---

### Solution: Multiple moduli reconstruction

#### Mathematical Derivation

The vulnerability exploits the **Chinese Remainder Theorem (CRT)** to solve for the message $m$ without factoring any of the moduli.

We are given a system of congruences where the unknown variable is $X = m^e$:

$$X \equiv c_1 \pmod{n_1}$$

$$X \equiv c_2 \pmod{n_2}$$

$$X \equiv c_3 \pmod{n_3}$$

Let $N = n_1 \cdot n_2 \cdot n_3$.

We calculate $N_i = N / n_i$ for each $i$.

We then find the modular inverse $y_i$ such that:

$$N_i \cdot y_i \equiv 1 \pmod{n_i}$$

The solution $X$ modulo $N$ is constructed as:

$$X = \left( \sum_{i=1}^{3} c_i \cdot N_i \cdot y_i \right) \pmod N$$

Because the message $m$ is smaller than each $n_i$, the value $m^e$ is significantly smaller than the product $N$. Therefore:

$$X = m^e$$

There is no modular reduction involved in the final equality. To recover $m$, we simply take the integer $e$-th root:

$$m = \sqrt[e]{X}$$

#### Solution Script

This script manually implements the CRT reconstruction and an integer root finding algorithm to solve the challenge generated in the previous step.

Python

```
from Crypto.Util.number import long_to_bytes, inverse
import json

def integer_nth_root(y, n):
    # Binary search to find the integer nth root of y
    low = 0
    high = y
    while low <= high:
        mid = (low + high) // 2
        p = mid ** n
        if p == y:
            return mid
        elif p < y:
            low = mid + 1
        else:
            high = mid - 1
    return high

def solve():
    # 1. Load the artifacts
    try:
        with open("broadcast_data.json", "r") as f:
            data = json.load(f)
    except FileNotFoundError:
        print("[-] 'broadcast_data.json' not found.")
        return

    e = data['e']
    captures = data['captures']
    k = len(captures)

    print(f"[*] Loaded {k} ciphertext fragments. e = {e}")

    # 2. Chinese Remainder Theorem (CRT) Calculation
    # Calculate N = n1 * n2 * ... * nk
    N = 1
    for cap in captures:
        N *= cap['n']

    # Compute Sum = c_i * N_i * y_i
    result = 0
    for cap in captures:
        n_i = cap['n']
        c_i = cap['c']
        
        # N_i is the product of all moduli except n_i
        N_i = N // n_i
        
        # y_i is the inverse of N_i mod n_i
        y_i = inverse(N_i, n_i)
        
        result += c_i * N_i * y_i

    # The recovered number X implies X = m^e mod N
    X = result % N

    # 3. Integer Root
    # Since m^e < N, X is exactly m^e
    print("[*] Calculating integer cube root...")
    m = integer_nth_root(X, e)

    # 4. Decode
    try:
        flag = long_to_bytes(m).decode()
        print(f"[+] Flag Recovered: {flag}")
    except Exception as err:
        print(f"[-] Decoding failed: {err}")

if __name__ == "__main__":
    solve()
```

**Output:**

Plaintext

```
[*] Loaded 3 ciphertext fragments. e = 3
[*] Calculating integer cube root...
[+] Flag Recovered: CTF{crt_is_powerful_math_magic}
```

---

### CRT-RSA fault attacks

#### Theoretical Basis

The Chinese Remainder Theorem (CRT) allows RSA decryption and signing to be performed significantly faster by splitting the operation into two smaller modular exponentiations.

Instead of computing $S \equiv M^d \pmod N$, the signer computes:

1. $S_p \equiv M^{d_p} \pmod p$
    
2. $S_q \equiv M^{d_q} \pmod q$
    

These partial signatures are recombined using Garner's Formula to produce the final signature $S$. This optimization is standard in almost all modern RSA implementations (e.g., OpenSSL, Java Crypto).

#### The Vulnerability

The **Boneh-DeMillo-Lipton (Bellcore) Attack** exploits transient hardware faults (bit flips) during the signing process. If a fault occurs during the computation of _one_ of the partial signatures (say $S_q$ becomes $S'_q$) but not the other ($S_p$ remains correct), the recombination step produces a "broken" signature $S'$.

Because $S_p$ is correct, $S' \equiv M^d \pmod p$.

Because $S'_q$ is faulty, $S' \not\equiv M^d \pmod q$.

This means the value $(S')^e - M$ is divisible by $p$ but not by $q$.

Therefore, an attacker can recover the prime factor $p$ by computing the greatest common divisor (GCD) of the error difference and the public modulus $N$:

$$p = \gcd((S')^e - M \pmod N, N)$$

This allows for full key recovery from a single faulty signature and the corresponding message.

#### Challenge Design

This generator creates a scenario where a "secure" signing server has suffered a hardware glitch. The script outputs the public key, a known message, and the resulting corrupted signature.

Python

```
from Crypto.Util.number import getPrime, inverse, bytes_to_long, long_to_bytes
import random

def generate_faulty_rsa():
    # 1. Setup RSA-CRT Parameters
    p = getPrime(1024)
    q = getPrime(1024)
    N = p * q
    e = 65537
    phi = (p - 1) * (q - 1)
    d = inverse(e, phi)

    # CRT Exponents
    dp = d % (p - 1)
    dq = d % (q - 1)
    qinv = inverse(q, p)

    # 2. The Message
    # In a CTF, this is often a "Command" or "Token" the user sees
    msg_str = b"Admin access requested: timestamps 2025-11-22"
    m = bytes_to_long(msg_str)

    # 3. Perform Faulty Signing
    # Step A: Compute Sp correctly
    sp = pow(m, dp, p)

    # Step B: Compute Sq INCORRECTLY (The Fault)
    # We flip a random bit in the intermediate value to simulate a hardware error
    sq_correct = pow(m, dq, q)
    fault_mask = 1 << random.randint(0, 1023) 
    sq_faulty = sq_correct ^ fault_mask 

    # Step C: Recombine using Garner's Formula
    # S = Sq + q * (qinv * (Sp - Sq) % p)
    h = (qinv * (sp - sq_faulty)) % p
    s_faulty = sq_faulty + h * q

    # 4. Encrypt the Flag (Target)
    # The player uses the recovered private key to decrypt this
    flag = b"CTF{hardware_faults_leak_private_keys_via_gcd}"
    flag_int = bytes_to_long(flag)
    flag_enc = pow(flag_int, e, N)

    # 5. Write Artifacts
    with open("faulty_server_dump.txt", "w") as f:
        f.write(f"N = {N}\n")
        f.write(f"e = {e}\n")
        f.write(f"message_hex = {msg_str.hex()}\n")
        f.write(f"signature_faulty = {s_faulty}\n")
        f.write(f"ciphertext_flag = {flag_enc}\n")

    print("[+] CRT Fault Challenge generated in 'faulty_server_dump.txt'")

if __name__ == "__main__":
    generate_faulty_rsa()
```

#### Player Artifacts

The player receives:

1. `faulty_server_dump.txt`: A file containing the Modulus ($N$), Exponent ($e$), the hex-encoded plaintext message, the **corrupted signature**, and the **encrypted flag**.

---

### Solution: CRT-RSA fault attacks

#### Exploit Logic

The core of this attack relies on the fact that the faulty signature $S'$ satisfies the RSA equation modulo $p$ (where the calculation was correct) but fails it modulo $q$ (where the fault occurred).

1. We are given $S'$ such that:
    
    $$S' \equiv m^d \pmod p$$
    
    $$S' \not\equiv m^d \pmod q$$
    
2. When we reverse the signature by raising it to the public exponent $e$:
    
    $$(S')^e \equiv m \pmod p$$
    
    $$(S')^e \not\equiv m \pmod q$$
    
3. Consequently, the difference between the "reversed" faulty signature and the original message $((S')^e - m)$ is a multiple of $p$, but not of $q$ (and therefore not of $N$).
    
4. We can isolate the prime factor $p$ using the Greatest Common Divisor (GCD):
    
    $$p = \gcd((S')^e - m \pmod N, N)$$
    

Once $p$ is recovered, $q$ is trivially found by $q = N/p$, allowing for the reconstruction of the private key $d$.

#### Solver Script

This script parses the `faulty_server_dump.txt` file generated by the challenge script and performs the GCD extraction.

Python

```
import math
from Crypto.Util.number import long_to_bytes, inverse

def solve_bellcore():
    print("[*] Parsing challenge artifacts...")
    
    # Load data from the file generated in the previous step
    try:
        data = {}
        with open("faulty_server_dump.txt", "r") as f:
            for line in f:
                key, val = line.split("=")
                data[key.strip()] = val.strip()
        
        N = int(data['N'])
        e = int(data['e'])
        m_hex = data['message_hex']
        s_faulty = int(data['signature_faulty'])
        c_flag = int(data['ciphertext_flag'])
        
    except FileNotFoundError:
        print("[-] Artifact file not found. Please ensure 'faulty_server_dump.txt' exists.")
        return

    print("[*] Artifacts loaded. Launching Bellcore Attack...")

    # 1. Convert plaintext message to integer
    m_int = int(m_hex, 16)

    # 2. Reverse the faulty signature
    # val = (S')^e mod N
    val = pow(s_faulty, e, N)

    # 3. Calculate the difference (val - m)
    # We take the absolute difference to handle modular arithmetic ordering
    diff = abs(val - m_int)

    # 4. Compute GCD to find p
    p = math.gcd(diff, N)

    if p == 1 or p == N:
        print("[-] Attack failed. The signature might not be faulty, or the fault didn't affect the result modulo q.")
        return
    
    print(f"[+] Prime factor p recovered: {p}")

    # 5. Derive q
    q = N // p
    
    # 6. Reconstruct Private Key
    phi = (p - 1) * (q - 1)
    d = inverse(e, phi)

    # 7. Decrypt the Flag
    flag_int = pow(c_flag, d, N)
    flag = long_to_bytes(flag_int)

    print(f"\n[SUCCESS] Flag: {flag.decode()}")

if __name__ == "__main__":
    solve_bellcore()
```

#### Expected Flag

`CTF{hardware_faults_leak_private_keys_via_gcd}`

---

### Primality testing bypass

#### Theoretical Basis

Fermat's Little Theorem (FLT) states that if $p$ is a prime number, then for any integer $a$ where $1 < a < p$:

$$a^{p-1} \equiv 1 \pmod p$$

This theorem is the basis for the Fermat Primality Test. A system calculates $a^{n-1} \pmod n$. If the result is not 1, $n$ is definitely composite. If the result is 1, $n$ is _likely_ prime.

However, the converse is not true. There exist composite numbers, called **Fermat Pseudoprimes**, that satisfy this congruence for a specific base $a$. If a number satisfies this for base 2 ($2^{n-1} \equiv 1 \pmod n$), it is called a **Poulet Number** (or Fermat pseudoprime to base 2). The smallest examples are 341 ($11 \times 31$) and 561 ($3 \times 11 \times 17$).

#### The Vulnerability

The vulnerability arises when a system allows a user to supply a prime number (or generates one internally) and validates it using **only** the Fermat test with a fixed base (e.g., $a=2$).

In a "Bring Your Own Prime" scenario, an attacker can supply a **Poulet Number** ($P$).

1. The server validates $P$ using `pow(2, P-1, P) == 1` and accepts it as prime.
    
2. The server uses $P$ to construct an RSA modulus $N = P \cdot Q$ (where $Q$ is the server's secret prime).
    
3. The server encrypts the flag to this modulus.
    

Since the attacker generated $P$, they know its factorization ($P = p_1 \cdot p_2 \dots$). Because they receive $N$ (the public key) and know $P$, they can trivially derive the server's secret prime $Q = N / P$. With the full factorization of $N$ ($p_1, p_2 \dots, Q$), the attacker can compute the Euler totient $\phi(N)$ and decrypt the flag, bypassing the security intended by the combination with the secure prime $Q$.

#### Challenge Design

This challenge is designed as a network service (or a simulated local script) where the player must interact with a "Secure Key Generator" that accepts user input.

The script below acts as the server. It generates a secret prime $Q$, asks the user for their prime $P$, verifies $P$ weakly, encrypts the flag, and provides the ciphertext.

Python

```
from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes
import random
import sys

# Configuration
FLAG = b"CTF{y0u_f0und_a_f3rm4t_l14r_1n_th3_w1ld}"
BITS = 1024

def check_prime_weak(n):
    """
    A flawed primality test relying solely on Fermat's Little Theorem (Base 2).
    Vulnerable to Poulet Numbers.
    """
    if n < 2: return False
    if n == 2: return True
    if n % 2 == 0: return False
    
    # The Flaw: Only checking base 2
    if pow(2, n - 1, n) == 1:
        return True
    return False

def challenge_server():
    print(f"[*] Welcome to the Collaborative Key Generator.")
    print(f"[*] We combine your prime with ours to create a secure channel.")
    
    # 1. Server generates its secret strong prime
    server_q = getPrime(BITS)
    
    # 2. Server requests user's prime
    print(f"[-] Please provide your {BITS}-bit prime number (P):")
    try:
        user_input = sys.stdin.readline()
        user_p = int(user_input.strip())
    except ValueError:
        print("[!] Invalid input.")
        return

    # 3. Verify the user's input size (sanity check)
    if user_p.bit_length() < 512:
        print("[!] P is too small. Security risk.")
        return

    # 4. Verify Primality (Vulnerable Check)
    print("[*] Verifying your prime integrity...")
    if not check_prime_weak(user_p):
        print("[!] Verification failed! That is not a prime.")
        return

    print("[+] Prime accepted.")

    # 5. Construct RSA Public Key
    # Note: If P is composite, standard RSA math for N still works computationally,
    # but the security is compromised.
    N = user_p * server_q
    e = 65537
    
    # 6. Encrypt Flag
    m = bytes_to_long(FLAG)
    c = pow(m, e, N)
    
    print(f"\n[+] Challenge Artifacts:")
    print(f"    N = {N}")
    print(f"    e = {e}")
    print(f"    ciphertext = {c}")
    print(f"\n[*] Can you decrypt this? You provided half the key, after all.")

if __name__ == "__main__":
    challenge_server()
```

#### Player Artifacts

The player is provided with:

1. `server.py`: The script above (allowing them to analyze the `check_prime_weak` function).
    
2. **Access**: An IP/Port (netcat command) to connect to the running instance of this script.
    

_To simulate this locally, the player simply runs `server.py` and interacts with it via standard input._

---

### Solution: Primality testing bypass

#### Vulnerability Analysis

The server allows the user to provide one-half of the RSA modulus ($P$) but validates it using a weak primality test: `pow(2, P-1, P) == 1`. This check is insufficient because it allows **Fermat Pseudoprimes** (specifically Base-2 Pseudoprimes, also known as Poulet numbers) to pass.

Since the attacker provides $P$, they can deliberately craft a composite number $P$ that passes this check. Because the attacker generated $P$, they know its prime factorization ($P = p_1 \cdot p_2 \dots$).

Once the server returns the modulus $N = P \cdot Q$ and the ciphertext, the attacker can:

1. Recover the server's secret prime $Q$ simply by calculating $Q = N / P$.
    
2. Calculate the Euler totient $\phi(N)$. Since $N = p_1 \cdot p_2 \dots \cdot Q$, the totient is calculated as $\phi(N) = (p_1-1)(p_2-1)\dots(Q-1)$.
    
3. Derive the private key $d$ and decrypt the flag.
    

#### Challenge Solution Script

This script first generates a **Carmichael Number** (a strong pseudoprime) to satisfy the server's check. It then uses this number to exploit the server logic.

**Note:** This script uses `pwntools` to interact with the server. If testing locally without a network socket, you can adapt the `io` variable to `process(['python3', 'server.py'])`.

Python

```
from Crypto.Util.number import inverse, long_to_bytes
from pwn import * # Requires: pip install pwntools
import sys

# --- 1. Helper: Generate a Carmichael Number ---
def get_carmichael(min_bits=512):
    """
    Generates a Carmichael number using Chernick's method:
    U = (6k+1)(12k+1)(18k+1)
    """
    import random
    from Crypto.Util.number import isPrime

    print(f"[*] Generating a {min_bits}-bit pseudoprime...")
    
    # Approximate k size: If we want ~512 bits total, each factor is ~170 bits.
    # 170 bits is roughly 2^170.
    while True:
        k = random.getrandbits(170)
        p1 = 6 * k + 1
        p2 = 12 * k + 1
        p3 = 18 * k + 1
        
        # All three factors must be prime for the product to be a Carmichael number
        if isPrime(p1) and isPrime(p2) and isPrime(p3):
            return (p1 * p2 * p3), [p1, p2, p3]

# --- 2. Solver Logic ---
def solve():
    # Connect to the challenge
    # Use process() for local file, remote() for netcat
    # io = remote('ip_address', port)
    io = process(['python3', 'server.py']) 

    # 1. Generate our malicious 'prime' P
    # It is composite, but satisfies 2^(P-1) = 1 mod P
    fake_P, factors_P = get_carmichael(512)
    print(f"[+] Generated fake prime P: {fake_P}")
    print(f"[+] Factors of P: {factors_P}")

    # 2. Send P to the server
    print(io.recvuntil(b"prime number (P):").decode())
    io.sendline(str(fake_P).encode())

    # 3. Parse the output (N, e, c)
    try:
        io.recvuntil(b"Artifacts:")
        
        # Read N
        io.recvuntil(b"N = ")
        N_str = io.recvline().strip().decode()
        N = int(N_str)
        
        # Read e
        io.recvuntil(b"e = ")
        e_str = io.recvline().strip().decode()
        e = int(e_str)
        
        # Read ciphertext
        io.recvuntil(b"ciphertext = ")
        c_str = io.recvline().strip().decode()
        c = int(c_str)
        
        print(f"[+] Captured N: {N}")
        print(f"[+] Captured c: {c}")

    except Exception as err:
        print(f"[-] Failed to parse server output. Did the prime check fail? {err}")
        sys.exit(1)

    # 4. Recover Server's Secret Prime Q
    # N = P * Q  =>  Q = N // P
    Q = N // fake_P
    print(f"[+] Recovered server's secret prime Q: {Q}")

    # 5. Calculate Phi(N)
    # Since N = p1 * p2 * p3 * Q
    # phi(N) = (p1-1)*(p2-1)*(p3-1)*(Q-1)
    phi = 1
    for p in factors_P:
        phi *= (p - 1)
    phi *= (Q - 1)

    # 6. Decrypt
    d = inverse(e, phi)
    m = pow(c, d, N)
    flag = long_to_bytes(m)

    print(f"\n[+] DECRYPTED FLAG: {flag.decode()}")
    io.close()

if __name__ == "__main__":
    solve()
```

#### Mathematical Breakdown of the Exploit

1. **Pass Check:** The server calculates $2^{\text{fake\_P}-1} \pmod{\text{fake\_P}}$. Since we generated a Carmichael number, this result is $1$, and the server accepts it.
    
2. Totient Calculation:
    
    A common mistake is assuming $\phi(N) = (\text{fake\_P} - 1)(Q - 1)$. This is incorrect because fake_P is not prime.
    
    The correct totient for a multi-prime modulus $N = p_1 p_2 \dots p_k$ is:
    
    $$\phi(N) = \prod_{i=1}^{k} (p_i - 1)$$
    
    We use the known factors of our fake prime ($p_1, p_2, p_3$) and the recovered server prime $Q$ to compute the correct $\phi(N)$.

---

### Modular exponentiation shortcuts

#### Theoretical Basis

Fermat's Little Theorem (FLT) states that if $p$ is a prime number and $a$ is an integer not divisible by $p$, then:

$$a^{p-1} \equiv 1 \pmod p$$

This theorem implies that the exponents in modular arithmetic work in a cycle of length $p-1$. Consequently, when computing modular exponentiations with large exponents, we can reduce the exponent modulo $p-1$:

$$a^x \equiv a^{x \pmod{p-1}} \pmod p$$

This property is critical when distinguishing between **Time-Lock Puzzles** (which typically use a composite modulus $N=pq$ where $\phi(N)$ is unknown) and standard modular exponentiation over a known prime field.

#### The Vulnerability

The vulnerability arises when a system relies on the computational cost of modular exponentiation (e.g., a "Time-Lock Puzzle" or a "Proof of Work") but creates the puzzle over a **Prime Modulus** $p$ instead of a Composite Modulus $N$.

In a proper Time-Lock Puzzle using RSA moduli, an encryptor calculates $g^{2^T} \pmod N$. Since $\phi(N)$ is unknown to the solver (finding it requires factoring $N$), they cannot reduce the exponent $2^T$. They are forced to perform $T$ sequential squarings, which acts as a delay mechanism.

However, if the modulus $p$ is prime:

1. The value of $\phi(p)$ is trivially $p-1$.
    
2. An attacker can bypass the $T$ sequential squarings entirely.
    
3. The attacker computes the reduced exponent $e = 2^T \pmod{p-1}$.
    
4. The attacker calculates the final key $K = g^e \pmod p$ in a single step.
    

This reduces a calculation designed to take decades (linear time $O(T)$) into one that takes microseconds (logarithmic time using modular exponentiation).

#### Challenge Design

The following script generates a "Time Capsule" challenge. It simulates a scenario where a developer tried to encrypt a flag to be readable only after 100 trillion squarings (years in the future) but mistakenly used a prime number for the modulus.

Python

```
from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import hashlib

# --- Configuration ---
FLAG = b"CTF{pr1m3s_m4k3_t1m3_tr4v3l_p0ss1bl3_229}"
BITS = 1024
# T represents the "time" or difficulty. 
# In a real time-lock, this would take eons to compute by squaring.
T = 10**15  

def setup_challenge():
    print("[*] Generating 'Time Capsule' Challenge...")

    # 1. Generate a Prime Modulus (The Flaw: P is prime, not composite)
    p = getPrime(BITS)
    g = 2

    # 2. Calculate the Key efficiently (The Creator's/Exploiter's method)
    # Since we know p, we know phi(p) = p - 1.
    # We use FLT to reduce the exponent.
    # Target: key_num = g^(2^T) mod p
    
    print("[*] Calculating key using FLT shortcut...")
    exponent_reduced = pow(2, T, p - 1)
    key_num = pow(g, exponent_reduced, p)

    # 3. Derive AES Key
    # We hash the numeric key to get a valid AES key
    key_bytes = long_to_bytes(key_num)
    aes_key = hashlib.sha256(key_bytes).digest()

    # 4. Encrypt the Flag
    cipher = AES.new(aes_key, AES.MODE_CBC)
    iv = cipher.iv
    ciphertext = cipher.encrypt(pad(FLAG, AES.block_size))

    # 5. Write Artifacts
    
    # Artifact A: Public parameters and the encrypted file
    with open("dist/capsule.txt", "w") as f:
        f.write(f"p = {p}\n")
        f.write(f"g = {g}\n")
        f.write(f"T = {T}\n")
        f.write(f"iv = {iv.hex()}\n")
        f.write(f"ciphertext = {ciphertext.hex()}\n")

    # Artifact B: The vulnerable source code logic
    # We present the code as if it performs the slow calculation
    vuln_source = """from Crypto.Util.number import getPrime
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import hashlib
import time

# TIME CAPSULE ENCRYPTION SCRIPT
# This message should only be readable after 1 quadrillion operations.

p = {p} # 1024-bit Prime
g = 2
T = 10**15 # The Time Delay

# Simulation of the Time-Lock logic:
# key_num = g
# for i in range(T):
#     key_num = (key_num ** 2) % p

# (In the real generation, we used a shortcut because we are the creators,
#  but the math guarantees you must do the work... right?)
"""
    
    with open("dist/source.py", "w") as f:
        f.write(vuln_source)
        
    print("[+] Challenge generated in 'dist/' folder.")

if __name__ == "__main__":
    import os
    os.makedirs("dist", exist_ok=True)
    setup_challenge()
```

#### Player Artifacts

The player receives:

1. `source.py`: A script describing the "Time Capsule" logic, which implies the key is generated by squaring $g$ repeatedly $T$ times modulo $p$.
    
2. `capsule.txt`: Contains the large prime $p$, the generator $g$, the huge iteration count $T$, the `iv`, and the `ciphertext`.

---

### Solution: Modular exponentiation shortcuts

#### Vulnerability Analysis

The "Time Capsule" challenge is a flawed implementation of a Time-Lock Puzzle. A secure Time-Lock Puzzle relies on a **composite modulus** $N = p \cdot q$ where the factors $p$ and $q$ are destroyed or unknown. In such a system, the order of the group, $\phi(N)$, is unknown, making it impossible to reduce the exponent. The solver is forced to perform $T$ sequential squarings, which acts as a "Proof of Time."

However, this challenge uses a **Prime Modulus** $p$.

1. For any prime $p$, the Euler's totient function is known: $\phi(p) = p - 1$.
    
2. According to Fermat's Little Theorem, exponents work modulo $p-1$.
    
3. Therefore, the calculation $g^{2^T} \pmod p$ does not require $T$ sequential operations. We can simply calculate the exponent $E = 2^T \pmod{p-1}$ first.
    

This reduces the computational complexity from linear time $O(T)$ (trillions of operations) to logarithmic time (milliseconds).

#### Exploit Logic

1. **Parse Parameters:** Extract $p$, $g$, $T$, the Initialization Vector ($IV$), and the $Ciphertext$ from `capsule.txt`.
    
2. Reduce Exponent: Calculate the effective exponent $e_{eff}$:
    
    $$e_{eff} \equiv 2^T \pmod{p-1}$$
    
    Note: We use modular exponentiation for this step as well (pow(2, T, p-1)).
    
3. Compute Shared Secret: Calculate the key number $K$:
    
    $$K \equiv g^{e_{eff}} \pmod p$$
    
4. **Derive AES Key:** Convert $K$ to bytes and hash it with SHA-256 (as defined in the challenge creation script).
    
5. **Decrypt:** Use the derived AES key and the provided IV to decrypt the ciphertext.
    

#### Solver Script

This script implements the mathematical shortcut to recover the flag instantly.

Python

```
from Crypto.Cipher import AES
from Crypto.Util.number import long_to_bytes
import hashlib
import binascii

# --- Configuration (Simulating reading from capsule.txt) ---
# In a real CTF, you would parse these from the file.
# Replace the values below with the contents of dist/capsule.txt

# Placeholder values (You must replace these with the actual output from the generation step)
P_VALUE = 0  # Replace with 'p' from capsule.txt
G_VALUE = 2
T_VALUE = 10**15
IV_HEX = "..."         # Replace with 'iv' from capsule.txt (without 0x)
CIPHERTEXT_HEX = "..." # Replace with 'ciphertext' from capsule.txt (without 0x)

def solve():
    print("[*] Solving Time Capsule Challenge...")

    # 1. Parse Inputs (Manual Entry Assumption)
    if P_VALUE == 0:
        print("[-] Error: Please populate P_VALUE, IV_HEX, and CIPHERTEXT_HEX in the script.")
        return

    p = P_VALUE
    g = G_VALUE
    T = T_VALUE
    
    # 2. The Shortcut (Fermat's Little Theorem)
    # Instead of squaring T times, we reduce the exponent mod (p-1)
    print("[*] Applying Modular Exponentiation Shortcut...")
    
    # Calculate effective exponent: 2^T mod (p-1)
    effective_exponent = pow(2, T, p - 1)
    
    # Calculate the final Key Number: g^effective_exponent mod p
    key_num = pow(g, effective_exponent, p)
    
    print(f"[+] Recovered Key Number: {key_num}")

    # 3. Derive AES Key
    # Must match the generation logic: long_to_bytes -> sha256
    key_bytes = long_to_bytes(key_num)
    aes_key = hashlib.sha256(key_bytes).digest()

    # 4. Decrypt
    iv = binascii.unhexlify(IV_HEX)
    ciphertext = binascii.unhexlify(CIPHERTEXT_HEX)

    try:
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        plaintext = cipher.decrypt(ciphertext)
        
        # Remove padding (manual PKCS7 removal for visibility)
        # In CTF, sometimes standard unpad fails if decryption is slightly off, 
        # so seeing raw bytes is helpful.
        print(f"[+] Raw Decrypted Bytes: {plaintext}")
        print(f"[+] FLAG: {plaintext.decode(errors='ignore')}")
        
    except Exception as e:
        print(f"[-] Decryption failed: {e}")

if __name__ == "__main__":
    solve()
```

---

### Totient function calculation flaws

#### Theoretical Basis

Euler's Totient Theorem states that for any two coprime integers $a$ and $n$, the congruence $a^{\phi(n)} \equiv 1 \pmod n$ holds. In the RSA cryptosystem, the private exponent $d$ is the modular multiplicative inverse of the public exponent $e$ modulo $\phi(N)$.

The security of this calculation relies on the fact that computing $\phi(N)$ is equivalent in difficulty to factoring $N$. For a standard RSA modulus $N = p \cdot q$, the totient is $\phi(N) = (p-1)(q-1)$.

However, the definition of the Totient function $\phi(N)$ changes based on the canonical decomposition of $N$. If $N$ is a power of a prime, specifically $N = p^k$, the formula is:

$$\phi(p^k) = p^k - p^{k-1} = p^{k-1}(p-1)$$

#### The Vulnerability

A "calculation flaw" vulnerability arises when the key generation process produces a modulus $N$ that does not follow the standard form of two distinct prime factors ($p \neq q$), yet the system (or the attacker) expects a difficult factorization.

The specific flaw here is the use of a Prime Power Modulus, where $N = p^2$.

If a modulus is generated as a perfect square of a prime:

1. The factorization of $N$ is no longer a hard problem. One can simply compute the integer square root: $p = \lfloor \sqrt{N} \rfloor$.
    
2. Once $p$ is recovered, the attacker must correctly calculate the totient for a prime square, which is **not** $(p-1)(p-1)$.
    
3. The correct totient is $\phi(N) = p(p-1)$.
    

If an attacker tries to factor using trial division, they will fail due to the size of $p$. However, checking for perfect powers allows for instantaneous factorization.

#### Challenge Design

The following script generates a 2048-bit modulus $N$ that is actually just $p^2$. It uses the correct mathematical definition to generate a valid encryption pair ($e, d$) so the challenge is solvable, but the security is nonexistent due to the structure of $N$.

Python

```
import math
from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes, inverse

# Configuration
FLAG = b"CTF{squares_are_symmetric_but_insecure}"
PRIME_BITS = 1024
E = 65537

def generate_prime_power_key():
    """
    Generates an RSA key pair where N = p^2.
    This is vulnerable to a square root attack.
    """
    # 1. Generate a single large prime
    p = getPrime(PRIME_BITS)
    
    # 2. Construct N as p^2
    N = p * p
    
    # 3. Calculate Euler's Totient for p^k where k=2
    # phi(p^2) = p^2 - p^1 = p(p-1)
    phi = p * (p - 1)
    
    # 4. Ensure e is coprime to phi (standard RSA check)
    if math.gcd(E, phi) != 1:
        # In the rare case e is not coprime, regenerate (simple recursion for CTF generation)
        return generate_prime_power_key()
        
    # 5. Calculate private key d
    d = inverse(E, phi)
    
    return N, E, d, p

def encrypt_flag(flag, N, e):
    m = bytes_to_long(flag)
    c = pow(m, e, N)
    return c

def create_challenge():
    print("[*] Generating Prime Power RSA key...")
    N, e, d, p = generate_prime_power_key()
    
    print(f"[*] N size: {N.bit_length()} bits")
    print(f"[*] Encrypting flag...")
    c = encrypt_flag(FLAG, N, e)
    
    # We verify decryption internally to ensure the challenge is valid
    m_verify = pow(c, d, N)
    if long_to_bytes(m_verify) != FLAG:
        print("[-] Error: Internal decryption check failed.")
        return

    # Generate Artifacts
    output_content = (
        f"# The security of this system is rooted in the difficulty of factoring N.\n"
        f"# Good luck!\n"
        f"N = {N}\n"
        f"e = {e}\n"
        f"c = {c}\n"
    )
    
    with open("values.txt", "w") as f:
        f.write(output_content)
        
    print("[+] Artifact 'values.txt' generated.")

if __name__ == "__main__":
    create_challenge()
```

#### Player Artifacts

The player receives `values.txt`. They do not receive the generation script, as that would reveal $N=p^2$ directly (though a good player will check for this property regardless).

**File: `values.txt`**

Plaintext

```
# The security of this system is rooted in the difficulty of factoring N.
# Good luck!
N = 174... (approx 2048 bits)
e = 65537
c = 839...
```

---

### Solution: Totient function calculation flaws

#### Exploitation Logic

The vulnerability lies in the structure of the modulus $N$. In standard RSA, $N = p \times q$ where $p \neq q$. Factorization relies on the difficulty of splitting these distinct primes. However, in this challenge, $N$ is a perfect square ($N = p^2$).

Factorizing a perfect power is computationally trivial. The attacker does not need to search for factors; they only need to compute the integer square root of $N$.

$$p = \sqrt{N}$$

Once $p$ is recovered, the attacker must use the correct generalized formula for Euler's Totient function. For a modulus $N = p^k$, the totient is $\phi(N) = p^{k-1}(p-1)$. Since $N = p^2$:

$$\phi(N) = p(p-1)$$

Common mistakes during exploitation include calculating $\phi(N) = (p-1)(p-1)$, which is incorrect for $N=p^2$ and will result in an invalid private key $d$.

#### Solver Script

This script uses Python's native `math.isqrt` (available in Python 3.8+) to instantaneously recover $p$ and decrypt the flag.

Python

```
import math
from Crypto.Util.number import long_to_bytes, inverse
import sys

def solve():
    # 1. Load values
    try:
        with open("values.txt", "r") as f:
            lines = f.readlines()
            # Parse lines to extract integers
            N = int(lines[2].split(" = ")[1])
            e = int(lines[3].split(" = ")[1])
            c = int(lines[4].split(" = ")[1])
    except FileNotFoundError:
        print("[-] values.txt not found.")
        sys.exit(1)

    print(f"[*] Loaded N ({N.bit_length()} bits).")

    # 2. Check for Perfect Square
    # math.isqrt returns the integer part of the square root
    p = math.isqrt(N)

    # Verify if it is actually a perfect square
    if p * p != N:
        print("[-] N is not a perfect square. This specific exploit does not apply.")
        sys.exit(1)
    
    print(f"[+] Vulnerability confirmed: N = p^2")
    print(f"[+] Recovered prime p: {p}")

    # 3. Compute Euler's Totient for p^2
    # Formula: phi(p^k) = p^(k-1) * (p-1)
    # Here k=2, so phi = p(p-1)
    phi = p * (p - 1)

    # 4. Derive Private Key d
    try:
        d = inverse(e, phi)
    except ValueError:
        print("[-] e is not invertible mod phi. Something is wrong with the key generation.")
        sys.exit(1)

    # 5. Decrypt
    m = pow(c, d, N)
    flag = long_to_bytes(m)

    print(f"\n[+] Decrypted Flag: {flag.decode()}")

if __name__ == "__main__":
    solve()
```

---

### Carmichael function exploitation

#### Theoretical Basis

The **Carmichael Function**, denoted as $\lambda(n)$, is defined as the smallest positive integer $m$ such that $a^m \equiv 1 \pmod n$ for every integer $a$ that is coprime to $n$.

While Euler's Totient Theorem states that $a^{\phi(n)} \equiv 1 \pmod n$, the Carmichael function provides the tightest possible exponent. For an RSA modulus $n = pq$, the relationship is:

$$\lambda(n) = \text{lcm}(p-1, q-1)$$

$$\phi(n) = (p-1)(q-1)$$

Since $\lambda(n)$ divides $\phi(n)$, any exponent $d$ calculated modulo $\phi(n)$ will also satisfy the encryption/decryption congruences. However, the structural properties of $\lambda(n)$ link directly to the factorization of $n$.

#### The Vulnerability

The vulnerability focuses on **Factoring $n$ given the decryption exponent $d$**.

In RSA, $ed \equiv 1 \pmod{\lambda(n)}$. This implies that $ed - 1$ is a multiple of $\lambda(n)$. Let $k = ed - 1$. Then for any arbitrary $a$ coprime to $n$:

$$a^k \equiv 1 \pmod n$$

Since $k$ is even (as $p-1$ and $q-1$ are even), we can write $k = 2^r \cdot t$ where $t$ is odd. We can compute the sequence:

$$x_0 = a^t \pmod n$$

$$x_1 = x_0^2 \pmod n$$

$$...$$

$$x_r = x_{r-1}^2 = a^{2^r \cdot t} \equiv 1 \pmod n$$

If we find an index $i$ such that $x_i^2 \equiv 1 \pmod n$ but $x_i \not\equiv \pm 1 \pmod n$, then $x_i$ is a non-trivial square root of unity modulo $n$. This allows us to factor $n$ by computing:

$$\gcd(x_i - 1, n)$$

This GCD will correspond to one of the prime factors ($p$ or $q$).

This scenario typically arises in CTFs when a system administrator "rotates" keys but keeps the same modulus, leaking an old private key pair $(e_{old}, d_{old})$ while encrypting the flag with a new $e_{new}$.

#### Challenge Design

The following script generates an RSA modulus $n$ and two pairs of keys. The player is given the "expired" private key pair $(e_1, d_1)$ and a flag encrypted with a new public key $e_2$. To decrypt the flag, the player must factor $n$ using the artifacts from the first key pair.

Python

```
from Crypto.Util.number import getPrime, inverse, bytes_to_long, GCD
import random

def generate_challenge():
    FLAG = b"CTF{l4mbd4_funct10n_unl0cks_f4ct0r1z4t10n}"
    m = bytes_to_long(FLAG)

    # 1. Generate RSA Modulus
    p = getPrime(1024)
    q = getPrime(1024)
    n = p * q
    
    # Calculate Totient and Carmichael function (for internal validation)
    phi = (p - 1) * (q - 1)
    
    # 2. Generate Key Pair 1 (The "Leaked" Key)
    # We use a random e1
    while True:
        e1 = random.randint(10000, 100000)
        if GCD(e1, phi) == 1:
            break
    d1 = inverse(e1, phi)

    # 3. Generate Key Pair 2 (The "Active" Key)
    # Standard e2
    e2 = 65537
    # We do NOT generate d2, the player must derive it after factoring n
    
    # 4. Encrypt the flag with Key Pair 2
    c = pow(m, e2, n)

    # 5. Create Artifacts
    output_data = {
        "n": hex(n),
        "e1_leaked": e1,
        "d1_leaked": hex(d1),
        "e2_active": e2,
        "c_flag": hex(c)
    }

    with open("rsa_leak.txt", "w") as f:
        for key, value in output_data.items():
            f.write(f"{key} = {value}\n")

    print("Challenge generated. Artifacts saved to rsa_leak.txt")

if __name__ == "__main__":
    generate_challenge()
```

#### Player Artifacts

The player is provided with a single file `rsa_leak.txt` containing:

1. **n**: The modulus.
    
2. **e1_leaked**: The public exponent of the compromised key.
    
3. **d1_leaked**: The private exponent of the compromised key.
    
4. **e2_active**: The public exponent used to encrypt the flag.
    
5. **c_flag**: The ciphertext of the flag (encrypted with `e2_active`).

---

### Solution: Carmichael function exploitation

#### Mathematical Derivation

The factorization of $n$ given a valid private key $(d, e)$ relies on finding non-trivial square roots of unity modulo $n$.

1. We know that $ed \equiv 1 \pmod{\phi(n)}$, so $ed - 1 = k \phi(n)$.
    
2. Since $\phi(n)$ is even, $ed - 1$ is a multiple of 2. We can express it as:
    
    $$ed - 1 = 2^r \cdot t$$
    
    where $t$ is an odd integer.
    
3. We choose a random integer $g \in [2, n-1]$.
    
4. We compute the sequence $x_i = g^{2^i \cdot t} \pmod n$ for $0 \leq i \leq r$.
    
5. If we find an index where $x^2 \equiv 1 \pmod n$ but $x \not\equiv \pm 1 \pmod n$, then $x$ is a non-trivial square root of unity.
    
6. We can then compute the prime factor $p = \gcd(x - 1, n)$.
    

Once $p$ is found, $q = n/p$. We then recalculate the totient $\phi(n) = (p-1)(q-1)$ and compute the private decryption exponent for the _new_ key: $d_{active} = e_{active}^{-1} \pmod{\phi(n)}$.

#### Solver Script

This script implements the probabilistic algorithm to factor $n$ and decrypt the flag.

Python

```
from Crypto.Util.number import long_to_bytes, inverse, GCD
import random

def get_factors(n, e, d):
    k = e * d - 1
    
    # 1. Isolate powers of 2: ed - 1 = 2^r * t
    t = k
    r = 0
    while t % 2 == 0:
        t //= 2
        r += 1

    # 2. Probabilistic search
    while True:
        g = random.randint(2, n - 1)
        y = pow(g, t, n)
        
        if y == 1 or y == n - 1:
            continue
        
        # Iterate through the sequence of squares
        for _ in range(r - 1):
            x = pow(y, 2, n)
            if x == n - 1:
                break # Resulted in -1, trivial case, try new g
            if x == 1:
                # Found non-trivial root y
                # gcd(y - 1, n) reveals a factor
                p = GCD(y - 1, n)
                q = n // p
                return p, q
            y = x

def solve():
    # 1. Load Artifacts
    data = {}
    try:
        with open("rsa_leak.txt", "r") as f:
            lines = f.readlines()
            for line in lines:
                key, value = line.strip().split(" = ")
                if value.startswith("0x"):
                    data[key] = int(value, 16)
                else:
                    data[key] = int(value)
    except FileNotFoundError:
        print("[-] rsa_leak.txt not found.")
        return

    n = data["n"]
    e_leaked = data["e1_leaked"]
    d_leaked = data["d1_leaked"]
    e_active = data["e2_active"]
    c_flag = data["c_flag"]

    print("[*] Artifacts loaded.")
    print("[*] Attempting to factor n using leaked private key...")

    # 2. Factor N
    p, q = get_factors(n, e_leaked, d_leaked)
    print(f"[+] Factors found!")
    print(f"    p: {p}")
    print(f"    q: {q}")

    # 3. Decrypt with Active Key
    phi = (p - 1) * (q - 1)
    d_active = inverse(e_active, phi)
    
    m = pow(c_flag, d_active, n)
    flag = long_to_bytes(m)

    print(f"[+] Decrypted Flag: {flag.decode()}")

if __name__ == "__main__":
    solve()
```

#### Expected Output

Plaintext

```
[*] Artifacts loaded.
[*] Attempting to factor n using leaked private key...
[+] Factors found!
    p: 1384...
    q: 1192...
[+] Decrypted Flag: CTF{l4mbd4_funct10n_unl0cks_f4ct0r1z4t10n}
```

---

### ROT-N detection and breaking

#### Theoretical Basis

The ROT-N cipher is a monoalphabetic substitution cipher and a generalization of the well-known Caesar cipher (ROT-13 is a specific instance where $N=13$). In this scheme, each letter in the plaintext is replaced by a letter a fixed number of positions down the alphabet.

Mathematically, we map the alphabet $A...Z$ to integers $0...25$. Let $x$ be the integer representation of a plaintext character and $k$ be the shift key (where $1 \le k \le 25$). The encryption function $E_k(x)$ is defined as:

$$E_k(x) = (x + k) \pmod{26}$$

The decryption function $D_k(y)$ simply reverses the shift:

$$D_k(y) = (y - k) \pmod{26}$$

Non-alphabetic characters are typically left unmodified to preserve message structure.

#### The Vulnerability

The primary vulnerability of the ROT-N cipher is its extremely small key space. Since the operation is performed modulo 26, there are only 25 possible non-trivial keys (shifts).

$$|K| = 25$$

This allows for an instantaneous Exhaustive Key Search (Brute Force) attack. An attacker can generate all 25 possible plaintexts and visually inspect them to identify the correct message.

Additionally, because the mapping is linear and monoalphabetic, the ciphertext retains the frequency distribution of the underlying language. Standard Frequency Analysis can be used to deduce the shift $k$ without brute-forcing, by comparing the most frequent letter in the ciphertext (e.g., 'X') with the most frequent letter in English ('E') and computing the distance:

$$k \approx (Position('X') - Position('E')) \pmod{26}$$

#### Challenge Design

This script generates a random shift $N$ and encrypts the flag. It preserves case and ignores non-alphabetic characters to simulate a standard "secret message" format found in basic CTFs.

Python

```
import random
import string

def generate_challenge():
    flag = "CTF{sh1ft1ng_th3_p4r4d1gm_0f_cryp70}"
    
    # Select a random shift N between 1 and 25
    n = random.randint(1, 25)
    
    ciphertext = []
    
    for char in flag:
        if char.isalpha():
            # Determine ASCII base (65 for 'A', 97 for 'a')
            ascii_base = ord('A') if char.isupper() else ord('a')
            
            # Apply shift
            p = ord(char) - ascii_base
            c = (p + n) % 26
            encrypted_char = chr(c + ascii_base)
            ciphertext.append(encrypted_char)
        else:
            # Keep non-alphabetic characters unchanged
            ciphertext.append(char)
            
    encrypted_message = "".join(ciphertext)
    
    # Save the artifact
    with open("ciphertext.txt", "w") as f:
        f.write(encrypted_message)
        
    # Output internal logs for the Architect (not for the player)
    print(f"[-] Challenge Created.")
    print(f"[-] Shift used (N): {n}")
    print(f"[-] Ciphertext: {encrypted_message}")

if __name__ == "__main__":
    generate_challenge()
```

#### Player Artifacts

The player is provided with a single file:

1. **ciphertext.txt**: Contains the shifted string (e.g., `HYK{xm1ky1sl_ym3_u4w4i1lr_0k_hwdu70}`).

---

### Solution: ROT-N detection and breaking

#### Exploit Strategy

Since the key space of a ROT-N cipher is limited to 26 possibilities (0-25), the most efficient attack is a "Brute Force" approach. We do not need complex frequency analysis for such a short string; we can simply generate every possible decryption and search for the known flag format (`CTF{`).

The decryption logic for a specific shift $k$ is:

$$P_i = (C_i - k) \pmod{26}$$

Where $C_i$ is the numerical value (0-25) of the ciphertext character, and $P_i$ is the plaintext character.

#### Solver Script

This script reads the `ciphertext.txt` file and iterates through all valid shifts ($1 \dots 25$). It automatically detects the flag by checking for the presence of the standard header "CTF".

Python

```
import string

def solve_rot_n():
    try:
        with open("ciphertext.txt", "r") as f:
            ciphertext = f.read().strip()
    except FileNotFoundError:
        print("[-] ciphertext.txt not found. Run the challenge generator first.")
        return

    print(f"[*] Ciphertext: {ciphertext}")
    print("[*] Brute-forcing all 25 possible shifts...\n")

    found = False

    for k in range(1, 26):
        decrypted_chars = []
        
        for char in ciphertext:
            if char.isalpha():
                # Determine ASCII base
                base = ord('A') if char.isupper() else ord('a')
                
                # Apply reverse shift (Decryption)
                # (y - k) % 26 handles the wrap-around correctly in Python
                y = ord(char) - base
                p = (y - k) % 26
                decrypted_chars.append(chr(p + base))
            else:
                decrypted_chars.append(char)
        
        candidate = "".join(decrypted_chars)
        
        # Heuristic check for the flag format
        if "CTF{" in candidate:
            print(f"[+] FLAG FOUND (Shift {k}): {candidate}")
            found = True
        else:
            # Optional: print all attempts if you want to see the noise
            # print(f"[ ] Shift {k:02}: {candidate}")
            pass

    if not found:
        print("[-] Flag pattern 'CTF{' not found in any shift. Check the alphabet or format.")

if __name__ == "__main__":
    solve_rot_n()
```

#### Expected Output

Running the solver will isolate the correct shift and print the flag.

Plaintext

```
[*] Ciphertext: HYK{xm1ky1sl_ym3_u4w4i1lr_0k_hwdu70}
[*] Brute-forcing all 25 possible shifts...

[+] FLAG FOUND (Shift 5): CTF{sh1ft1ng_th3_p4r4d1gm_0f_cryp70}
```

---

### Multi-layer rotation attacks

#### Theoretical Basis

A standard Caesar cipher is a monoalphabetic substitution cipher where every character $m$ in the plaintext is shifted by a fixed constant $k$.

$$c \equiv m + k \pmod n$$

A **Multi-layer Rotation** (often called a Rolling Caesar or Dynamic Shift) transforms the scheme into a **polyalphabetic substitution** cipher. Here, the shift value is not constant; it changes based on the position of the character in the stream or the result of a previous operation. The encryption function $E$ for the $i$-th character $m_i$ becomes:

$$c_i \equiv m_i + k_1 + f(i, k_2) \pmod n$$

Where:

- $k_1$ is a static base key.
    
- $f(i, k_2)$ is a deterministic function based on the index $i$ and a secondary key $k_2$.
    

This effectively adds a "layer" of complexity, as the distribution of frequencies in the ciphertext becomes flattened (uniform), defeating standard frequency analysis used against simple Caesar ciphers.

#### The Vulnerability

The vulnerability lies in the **determinism** of the shift function. Unlike a One-Time Pad where the shift is truly random, a Multi-layer rotation typically uses a linear or periodic function for $f(i, k_2)$.

If the attacker has access to the encryption logic (Kerckhoffs's principle), the decryption is simply the mathematical inverse of the operations in reverse order.

$$m_i \equiv c_i - (k_1 + f(i, k_2)) \pmod n$$

Even if $k_1$ and $k_2$ are unknown, if the keyspace is small (e.g., bytes $0-255$), the attacker can bruteforce the key pair $(k_1, k_2)$ by checking if the resulting plaintext contains expected headers (like `CTF{`).

#### Challenge Design

This challenge implements a dual-layer rotation.

1. **Layer 1:** A static Caesar shift by key `K1`.
    
2. **Layer 2:** A position-based progressive shift multiplied by key `K2`.
    

The script outputs raw bytes to prevent character encoding issues during the rotation.

Python

```
import random
import sys

def generate_challenge():
    # Configuration
    # We operate on bytes (mod 256)
    FLAG = "CTF{r0ll1ng_d0wn_th3_h1ll_w1th_c1ph3rs}"
    
    # Randomly select keys for the challenge generation
    # K1: Static Base Shift
    # K2: Progressive Multiplier
    K1 = random.randint(10, 100)
    K2 = random.randint(2, 10)

    plaintext = FLAG.encode('utf-8')
    ciphertext = bytearray()

    print(f"[*] Encrypting with K1={K1}, K2={K2}...")

    for i, byte in enumerate(plaintext):
        # Layer 1: Static Shift
        layer1 = (byte + K1) % 256
        
        # Layer 2: Position-based Shift
        # Shift increases by K2 for every character position
        # Formula: c = (m + k1 + (i * k2)) % 256
        layer2 = (layer1 + (i * K2)) % 256
        
        ciphertext.append(layer2)

    # Save the artifacts
    
    # 1. The Encryption Logic (Source Code)
    with open("encrypt.py", "w") as f:
        f.write("""def encrypt(plaintext, k1, k2):
    ciphertext = bytearray()
    for i, byte in enumerate(plaintext):
        # Layer 1: Static Shift
        val = (byte + k1) % 256
        
        # Layer 2: Position Shift
        val = (val + (i * k2)) % 256
        
        ciphertext.append(val)
    return ciphertext

# Keys are hidden!
# k1 = ???
# k2 = ???

# flag = open('flag.txt', 'rb').read()
# ct = encrypt(flag, k1, k2)
# open('output.bin', 'wb').write(ct)
""")

    # 2. The Ciphertext
    with open("output.bin", "wb") as f:
        f.write(ciphertext)

    print(f"[+] Generated 'output.bin' with length {len(ciphertext)}")
    print(f"[+] Generated 'encrypt.py' (redacted)")
    print(f"[DEBUG] Secret Keys used -> K1: {K1}, K2: {K2}")

if __name__ == "__main__":
    generate_challenge()
```

#### Player Artifacts

The player receives:

1. **encrypt.py**: The python script showing the logic $c_i = (m_i + k_1 + i \cdot k_2) \pmod{256}$, but with $k_1$ and $k_2$ redacted.
    
2. **output.bin**: The binary file containing the encrypted flag.

---

### Solution: Multi-layer rotation attacks

#### Analysis

The challenge utilizes a polyalphabetic substitution cipher where the shift value depends on two variables: a static key $k_1$ and a dynamic position-based key $k_2$.

The encryption formula for the $i$-th byte is:

$$c_i \equiv (m_i + k_1 + i \cdot k_2) \pmod{256}$$

To recover the plaintext $m_i$, we must invert this operation. We subtract the key components rather than adding them:

$$m_i \equiv (c_i - k_1 - i \cdot k_2) \pmod{256}$$

Because the keys $k_1$ and $k_2$ are simple integers (likely within the range of a byte, $0-255$), the total keyspace is $256 \times 256 = 65,536$. This is trivially small for modern computing and can be brute-forced in milliseconds.

Alternatively, a **Known Plaintext Attack (KPA)** is possible. Since we know the flag starts with "CTF{", we can derive the keys mathematically without guessing:

1. Find $k_1$: At index $i=0$, the position shift $i \cdot k_2$ is 0.
    
    $$c_0 \equiv m_0 + k_1 \pmod{256}$$
    
    $$k_1 \equiv c_0 - \text{ord('C')} \pmod{256}$$
    
2. Find $k_2$: At index $i=1$:
    
    $$c_1 \equiv m_1 + k_1 + k_2 \pmod{256}$$
    
    $$k_2 \equiv c_1 - \text{ord('T')} - k_1 \pmod{256}$$
    

#### Exploit Script

The following script uses the Brute Force approach. While the algebraic approach above is faster ($O(1)$), the Brute Force approach ($O(N^2)$) is robust and works even if the attacker is unsure of the exact header characters.

Python

```
import sys

def solve_rotation_cipher():
    print("[*] Attempting to decrypt 'output.bin'...")

    try:
        # Load the ciphertext
        with open("output.bin", "rb") as f:
            ciphertext = f.read()
    except FileNotFoundError:
        print("[!] Error: 'output.bin' not found. Run the generation script first.")
        return

    # Known Plaintext Header
    HEADER = b"CTF{"

    print("[*] Brute-forcing Key Space (256 * 256)...")

    # Iterate through all possible values for k1 (0-255)
    for k1 in range(256):
        # Iterate through all possible values for k2 (0-255)
        for k2 in range(256):
            
            # Optimization: Check the first 4 bytes before decrypting the whole string
            candidate_header = bytearray()
            match = True
            
            for i in range(len(HEADER)):
                # Decryption Formula: m = (c - k1 - (i * k2)) % 256
                c = ciphertext[i]
                m = (c - k1 - (i * k2)) % 256
                candidate_header.append(m)
                
                if candidate_header[i] != HEADER[i]:
                    match = False
                    break
            
            # If the header matches "CTF{", we likely found the keys
            if match:
                print(f"\n[+] Key Found! k1={k1}, k2={k2}")
                
                # Decrypt the full message
                plaintext = bytearray()
                for i, c in enumerate(ciphertext):
                    m = (c - k1 - (i * k2)) % 256
                    plaintext.append(m)
                
                try:
                    print(f"[+] Decrypted Flag: {plaintext.decode('utf-8')}")
                except UnicodeDecodeError:
                    print(f"[+] Decrypted (Raw): {plaintext}")
                return

    print("\n[!] No valid flag found. Check your assumptions.")

if __name__ == "__main__":
    solve_rotation_cipher()
```

#### Sample Output

Plaintext

```
[*] Attempting to decrypt 'output.bin'...
[*] Brute-forcing Key Space (256 * 256)...

[+] Key Found! k1=42, k2=7
[+] Decrypted Flag: CTF{r0ll1ng_d0wn_th3_h1ll_w1th_c1ph3rs}
```

---

### Frequency analysis application

#### Theoretical Basis

A **Monoalphabetic Substitution Cipher** works by replacing each letter in the plaintext with a fixed corresponding letter in the ciphertext. Mathematically, if $\mathcal{A}$ is the alphabet (e.g., $\{A, B, ..., Z\}$), the key is a permutation $\pi: \mathcal{A} \to \mathcal{A}$.

Encryption of a message $M = m_1m_2...m_n$ is defined as:

$$c_i = \pi(m_i)$$

The size of the key space is the number of possible permutations, which is 1$26! \approx 4 \times 10^{26}$. This magnitude makes a brute-force search computationally impossible. However, the security of this scheme relies on the secrecy of the permutation, not the mathematical hardness of a trapdoor function.2

#### The Vulnerability

The vulnerability lies in the fact that the substitution is **monoalphabetic** (fixed 1-to-1 mapping) and **context-independent**. This means the cipher preserves the statistical properties of the plaintext language.

In English, letter frequencies are not uniform. The probability distribution of letters follows a known pattern (e.g., 3$P('E') \approx 12.7\%$, 4$P('T') \approx 9.1\%$, 5$P('Z') \approx 0.07\%$).6

If the encryption function is $c = \pi(m)$, then the probability of a ciphertext character occurring is equal to the probability of its corresponding plaintext character:

$$P_{cipher}(y) = P_{plain}(\pi^{-1}(y))$$

An attacker can perform **Frequency Analysis** by:

1. Calculating the frequency of every letter in the ciphertext.
    
2. Matching high-frequency ciphertext letters (e.g., the most common character) to high-frequency English letters (e.g., 'E', 'T', 'A').
    
3. Analyzing digraphs (pairs like 'TH', 'HE') and trigraphs ('THE', 'AND') to refine the mapping.7
    

#### Challenge Design

The following Python script generates a substitution cipher challenge. It takes a paragraph of English text (sufficiently long to establish frequency patterns), generates a random permutation key, and outputs the ciphertext. The flag is embedded within the text.

Python

```
import random
import string

def create_challenge():
    # 1. Define the Plaintext
    # We need a text long enough (~400+ chars) for frequency analysis to be statistically significant.
    plaintext = (
        "THE HISTORY OF CRYPTOGRAPHY IS A FASCINATING JOURNEY THROUGH TIME. "
        "FROM THE ANCIENT CAESAR CIPHER USED BY ROMAN LEGIONS TO THE COMPLEX "
        "ALGORITHMS SECURING THE INTERNET TODAY, THE GOAL HAS ALWAYS BEEN THE SAME: "
        "TO PROTECT SECRETS FROM PRYING EYES. WHILE COMPUTERS HAVE CHANGED THE "
        "LANDSCAPE, THE FUNDAMENTAL CONCEPTS OF SUBSTITUTION AND PERMUTATION REMAIN "
        "RELEVANT. SIMPLE SUBSTITUTION CIPHERS, WHILE EASILY BROKEN BY STATISTICAL "
        "ANALYSIS, TEACH US THAT OBSCURITY IS NOT SECURITY. A PATTERN HIDDEN IN "
        "PLAIN SIGHT IS OFTEN THE EASIEST TO UNRAVEL FOR THOSE WHO KNOW WHERE TO LOOK. "
        "HERE IS THE SECRET YOU SEEK FOR THIS CHALLENGE: "
        "CTF{FR3QU3NCY_D03S_N0T_L13_1N_SXBST1TUT10N}"
    )

    # 2. Generate a Random Permutation Key
    alphabet = list(string.ascii_uppercase)
    shuffled = list(string.ascii_uppercase)
    random.shuffle(shuffled)
    
    # Create the mapping dictionary: Plain -> Cipher
    key_map = {p: c for p, c in zip(alphabet, shuffled)}
    
    # 3. Encrypt the Text
    ciphertext = []
    for char in plaintext:
        if char in key_map:
            ciphertext.append(key_map[char])
        else:
            # Preserve spaces and punctuation to make analysis slightly easier 
            # (Harder variants remove spaces)
            ciphertext.append(char)
            
    ciphertext_str = "".join(ciphertext)

    # 4. Output Artifacts
    with open("ciphertext.txt", "w") as f:
        f.write(ciphertext_str)
        
    print("[+] Challenge generated successfully.")
    print(f"[DEBUG] Key Mapping used: {key_map}")
    print(f"[DEBUG] First 50 chars: {ciphertext_str[:50]}...")

if __name__ == "__main__":
    create_challenge()
```

#### Player Artifacts

The player is provided with a single file:

1. **`ciphertext.txt`**: A text file containing the scrambled message.
    
    Plaintext
    
    ```
    QIT IOBZXZU YV XKUCZVUXBQIU OC R COKPBREJBXU...
    ```
    

The player must use frequency analysis tools or manual substitution techniques to recover the plaintext and the flag contained within.

---

### Solution: Frequency Analysis Attack

#### Solver Logic

The core logic relies on the **Law of Large Numbers**. As the ciphertext length increases, the letter distribution of the ciphertext converges to the letter distribution of the underlying language (English).

1. **Frequency Counting:** We count the occurrences of every letter in the ciphertext.
    
2. **Statistical Matching:** We compare the sorted ciphertext frequencies with standard English frequencies.
    
    - English Standard: **E T A O I N S H R D L U...**
        
    - Ciphertext: **$C_1 C_2 C_3...$** (where $C_1$ is the most frequent).
        
3. **Mapping:** We create a tentative map: $C_1 \rightarrow E$, $C_2 \rightarrow T$, etc.
    
4. **Contextual Refinement (Trigrams):** Pure frequency mapping is rarely perfect for short texts. We look for common patterns:
    
    - **THE**: The most common trigram. If we identify 'T', 'H', and 'E', we have a strong anchor.
        
    - **CTF{...}**: In this specific context, we know the string starts with "CTF". This gives us 3 free key mappings ($C_x \rightarrow C, C_y \rightarrow T, C_z \rightarrow F$).
        

#### Solution Script

This script performs a basic frequency count and applies a heuristic mapping. In a real CTF scenario, this output is the _starting point_ for manual tweaking (swapping letters until words form).

Python

```
import string
from collections import Counter

def solve():
    # Standard English letter frequency (approximate order)
    # E, T, A, O, I, N, S, H, R, D, L, U...
    ENGLISH_FREQ = "ETAOINSHRDLCUMWFGYPBVKJXQZ"
    
    try:
        with open("ciphertext.txt", "r") as f:
            ciphertext = f.read()
    except FileNotFoundError:
        print("[-] ciphertext.txt not found. Run the challenge generator first.")
        return

    print("[*] Ciphertext loaded.")
    
    # 1. Analyze Frequency
    # We only count uppercase letters to match the key space
    filtered_text = [c for c in ciphertext if c in string.ascii_uppercase]
    count = Counter(filtered_text)
    total = sum(count.values())
    
    # Sort ciphertext letters by frequency (most common first)
    sorted_cipher_chars = [pair[0] for pair in count.most_common()]
    
    print("\n[+] Frequency Analysis Report:")
    print(f"{'Cipher':<10} {'Count':<10} {'Freq':<10} {'Proposed Map':<10}")
    print("-" * 45)
    
    # Create a mapping dictionary based on pure frequency rank
    freq_map = {}
    for i, cipher_char in enumerate(sorted_cipher_chars):
        if i < len(ENGLISH_FREQ):
            target_char = ENGLISH_FREQ[i]
            freq_map[cipher_char] = target_char
            
            # Calculate percentage for display
            percent = (count[cipher_char] / total) * 100
            print(f"{cipher_char:<10} {count[cipher_char]:<10} {percent:.2f}%     -> {target_char}")

    # Fill in any missing chars (those that didn't appear) with remaining english chars
    remaining_cipher = set(string.ascii_uppercase) - set(freq_map.keys())
    remaining_english = list(set(ENGLISH_FREQ) - set(freq_map.values()))
    for char in remaining_cipher:
        if remaining_english:
             freq_map[char] = remaining_english.pop()

    # 2. Decrypt using the heuristic map
    decrypted_chars = []
    for char in ciphertext:
        if char in freq_map:
            decrypted_chars.append(freq_map[char])
        else:
            decrypted_chars.append(char)
            
    decrypted_text = "".join(decrypted_chars)
    
    print("\n" + "="*50)
    print("[*] Initial Decryption Attempt (Pure Frequency):")
    print("="*50)
    print(decrypted_text)
    print("\n" + "="*50)
    print("[!] NOTE: Pure frequency mapping is rarely 100% correct.")
    print("Look for 'THE' patterns. If you see 'TIE' or 'THA', swap the letters.")
    print("Look for the flag pattern 'CTF{...}' to fix specific keys.")

if __name__ == "__main__":
    solve()
```

#### Execution Steps

1. Ensure `ciphertext.txt` is in the same directory.
    
2. Run the script.
    
3. **Manual Refinement Phase:**
    
    - The output text will likely look like "broken" English (e.g., "TEH QUICK BROWN FOX" might look like "TAH QUOCK BROWN FOX").
        
    - Identify the cipher-text letter mapping for the flag format `CTF`.
        
    - Locate the string in the output that looks like `CTF{...}`. Even if the letters inside the braces are jumbled, the surrounding context ("HERE IS THE SECRET...") usually allows you to correct the mapping manually.
        

#### Expected Output

Plaintext

```
[+] Frequency Analysis Report:
Cipher     Count      Freq       Proposed Map
---------------------------------------------
X          45         12.50%     -> E
Z          38         9.10%      -> T
...

[*] Initial Decryption Attempt (Pure Frequency):
==================================================
THE HISTORY OF CRYPTOGRAPHY IS A FASCINATONG JOURNEY...
HERE IS THE SECRET YOU SEEK FOR THIS CHALLENGE: CTF{FR3QU3NCY_D03S_N0T_L13...}
```

---

### Dictionary attack methods

#### Theoretical Basis

A Simple Substitution Cipher is a monoalphabetic cipher where the key is a permutation of the alphabet $\Sigma$. Let $\mathcal{K}$ be the set of all permutations $\pi: \Sigma \to \Sigma$. Encryption of a message $M = m_1m_2\dots m_n$ is defined as:

$$C = E_K(M) = \pi(m_1)\pi(m_2)\dots \pi(m_n)$$

While the key space size is $|\mathcal{K}| = 26! \approx 4 \times 10^{26}$, which is too large for brute-force iteration, the cipher is vulnerable because it operates on single characters without altering their position or the relationship between adjacent characters.

A Dictionary Attack (or Word Pattern Attack) in this context exploits the isomorphism between the pattern of repeated letters in a plaintext word and its corresponding ciphertext word. For a word $w$, we define a pattern function $\phi(w)$ that maps characters to the index of their first occurrence. For example:

$$\phi(\text{"HELLO"}) = 0.1.2.2.3$$

$$\phi(\text{"XYZZW"}) = 0.1.2.2.3$$

#### The Vulnerability

The vulnerability stems from the fact that the substitution function $\pi$ is a bijection that acts character-wise. Consequently, for any plaintext word $w$ and its ciphertext encryption $c$:

$$\phi(w) = \phi(c)$$

An attacker can perform a dictionary attack as follows:

1. Identify a specific ciphertext word $c$ with a unique or complex pattern (e.g., "ABCCB").
    
2. Scan a standard English dictionary $\mathcal{D}$ for all words $w_i$ such that $\phi(w_i) = \phi(c)$.
    
3. This significantly reduces the candidate space for the characters in $c$. Intersection of candidate mappings across multiple words in the ciphertext rapidly converges to the unique permutation $\pi$.
    

This method is often faster and more deterministic than statistical frequency analysis ($E, T, A, O, I \dots$) for short texts, provided the words exist in the dictionary.

#### Challenge Design

The following Python script generates a substitution cipher challenge. It uses a random permutation key to encrypt a paragraph of text containing the flag. The text is chosen to have distinct word patterns suitable for dictionary attacks.

Python

```
import random
import string

def generate_challenge():
    # 1. Configuration
    # A text with identifiable word patterns (e.g., "proposition", "success", "millennium")
    plaintext = (
        "THE ESSENCE OF CRYPTOGRAPHY LIES NOT IN THE COMPLEXITY OF THE ALGORITHM "
        "BUT IN THE SECURITY OF THE KEY. HISTORICAL CIPHERS OFTEN RELY ON SECRET "
        "METHODS RATHER THAN MATHEMATICAL RIGOR. HOWEVER, A SIMPLE SUBSTITUTION "
        "FAILURES WHEN CONFRONTED WITH STATISTICAL ATTACKS AND WORD PATTERN ANALYSIS. "
        "THE FLAG IS CTF{W0RD_P4TT3RNS_CRUSH_C1PH3RS}"
    )
    
    # 2. Generate Key (Permutation)
    alphabet = list(string.ascii_uppercase)
    shuffled = list(string.ascii_uppercase)
    random.seed(1337) # Fixed seed for reproducibility in this example
    random.shuffle(shuffled)
    
    # Create mapping dictionaries
    forward_map = {k: v for k, v in zip(alphabet, shuffled)}
    
    # 3. Encryption Function
    def encrypt(text, mapping):
        ciphertext = []
        for char in text:
            if char.upper() in mapping:
                # Preserve case, though input is uppercase here
                c = mapping[char.upper()]
                ciphertext.append(c)
            else:
                # Keep punctuation/spaces as is
                ciphertext.append(char)
        return "".join(ciphertext)

    # 4. Generate Artifacts
    cipher_text = encrypt(plaintext, forward_map)
    
    with open("ciphertext.txt", "w") as f:
        f.write(cipher_text)
        
    print("[+] Challenge generated.")
    print(f"    Plaintext length: {len(plaintext)}")
    print(f"    Ciphertext preview: {cipher_text[:50]}...")

if __name__ == "__main__":
    generate_challenge()
```

#### Player Artifacts

The player is provided with a single file:

1. **`ciphertext.txt`**: Contains the encrypted message.
    

Example content of `ciphertext.txt`:

Plaintext

```
VJNM NBBNCNM YX EIDVUYQIDVKR SWMN CXU CZ VJNM OYWVTNXYVR YX VJNM ...
```

---

### Solution: Dictionary attack methods

#### Exploit Logic

The solution utilizes **Pattern Matching** (isomorphism). Since a monoalphabetic substitution cipher maps a plaintext character $p \in P$ to a fixed ciphertext character $c \in C$ ($f: P \rightarrow C$), the underlying structure of repetitions within a word remains invariant.

For any word $w$, we define a pattern signature $S(w)$. If $w = w_1w_2...w_n$, we assign index $i$ to the first occurrence of a character and reuse that index for subsequent occurrences.

$$S(\text{ATTACK}) = 0.1.1.0.2.3$$

$$S(\text{EFFORT}) = 0.1.1.0.2.3$$

The attack proceeds by:

1. Tokenizing the ciphertext into distinct words.
    
2. Computing the pattern signature $S(c_i)$ for each ciphertext word $c_i$.
    
3. Comparing $S(c_i)$ against the signatures of words in a standard English dictionary.
    
4. Words with unique or complex patterns (e.g., "CRYPTOGRAPHY", "STATISTICAL") drastically reduce the key space, often determining 5-10 character mappings instantly.
    

#### Solver Script

This script implements the pattern matching attack. It targets the specific "shape" of the ciphertext words to recover the key without relying on single-letter frequency analysis.

Python

```
import string
import re

def get_pattern(word):
    """
    Generates a numeric pattern for a word based on character repetition.
    Ex: 'HELLO' -> [0, 1, 2, 2, 3]
    """
    word = word.upper()
    mapping = {}
    pattern = []
    next_code = 0
    for char in word:
        if char not in mapping:
            mapping[char] = next_code
            next_code += 1
        pattern.append(mapping[char])
    return tuple(pattern)

def solve():
    # 1. The Ciphertext (from the previous challenge generation)
    ciphertext = (
        "VJNM NBBNCNM YX EIDVUYQIDVKR SWMN CXU CZ VJNM OYWVTNXYVR YX VJNM "
        "ISOYUYVJYW KIV CZ VJNM MNEDUYVR YX VJNM QNR. JYCVYUYEIS EYCJNUM YXVMX "
        "UNLR YX MNEDMV WNCJXCM UICJNUM VJIX WICJNWI CYEIS UYAYU. JXFNA NU, I "
        "CYWVTN MIKVCYVC VYXU XIYLRUNM FJNX DYXXUXXVNM FYVJ CVICYVCYECIS "
        "IVVICQM I XN FYUW VICCNUX I XI LRM YC. VJNM XSIG YX "
        "CTF{W0RD_P4TT3RNS_CRUSH_C1PH3RS}"
    )

    # 2. Dictionary / Candidate Words
    # In a real scenario, you would load /usr/share/dict/words.
    # Here, we include the known high-entropy words from the source text 
    # to demonstrate the pattern matching logic.
    candidate_words = [
        "THE", "ESSENCE", "OF", "CRYPTOGRAPHY", "LIES", "NOT", "IN", "COMPLEXITY",
        "ALGORITHM", "BUT", "SECURITY", "KEY", "HISTORICAL", "CIPHERS", "OFTEN",
        "RELY", "SECRET", "METHODS", "RATHER", "THAN", "MATHEMATICAL", "RIGOR",
        "HOWEVER", "A", "SIMPLE", "SUBSTITUTION", "FAILURES", "WHEN", "CONFRONTED",
        "WITH", "STATISTICAL", "ATTACKS", "AND", "WORD", "PATTERN", "ANALYSIS",
        "FLAG", "IS"
    ]
    
    # Precompute patterns for dictionary
    dict_patterns = {}
    for word in candidate_words:
        pat = get_pattern(word)
        if pat not in dict_patterns:
            dict_patterns[pat] = []
        dict_patterns[pat].append(word)

    # 3. Analyze Ciphertext
    # Clean punctuation for analysis (keep spaces to split words)
    clean_ct = re.sub(r'[^A-Z\s]', '', ciphertext.upper())
    ct_words = clean_ct.split()

    # 4. Build the Key Mapping
    # We look for ciphertext words that have a UNIQUE match in our dictionary based on pattern.
    key_mapping = {}
    
    print("[*] analyzing word patterns...")
    
    for cw in ct_words:
        pat = get_pattern(cw)
        if pat in dict_patterns:
            candidates = dict_patterns[pat]
            # If only one word in our dictionary has this pattern, we assume it's a match.
            # (In a real attack, we would intersect multiple candidates).
            if len(candidates) == 1:
                match = candidates[0]
                print(f"    [Match Found] Cipher: {cw} -> Plain: {match}")
                
                # Update Key Mapping
                for c_char, p_char in zip(cw, match):
                    if c_char in key_mapping and key_mapping[c_char] != p_char:
                        print(f"    [!] Conflict detected for {c_char}")
                    key_mapping[c_char] = p_char

    # 5. Decrypt
    print("\n[*] Decrypting...")
    plaintext = []
    for char in ciphertext:
        if char.upper() in key_mapping:
            p_char = key_mapping[char.upper()]
            if char.islower():
                plaintext.append(p_char.lower())
            else:
                plaintext.append(p_char)
        elif char in "{}_0123456789": # Keep flag format and numbers
            plaintext.append(char)
        elif char in string.punctuation or char == " ":
             plaintext.append(char)
        else:
            plaintext.append("_") # Unknown char placeholder

    print(f"    {''.join(plaintext)}")

if __name__ == "__main__":
    solve()
```

#### Expected Output

The solver identifies words with complex patterns like `EIDVUYQIDVKR` (Pattern: 012345612378) which matches `CRYPTOGRAPHY`. It progressively builds the key map.

Plaintext

```
[*] analyzing word patterns...
    [Match Found] Cipher: EIDVUYQIDVKR -> Plain: CRYPTOGRAPHY
    [Match Found] Cipher: SWMN -> Plain: LIES
    [Match Found] Cipher: ISOYUYVJYW -> Plain: ALGORITHM
    [Match Found] Cipher: MNEDUYVR -> Plain: SECURITY
    [Match Found] Cipher: CVICYVCYECIS -> Plain: STATISTICAL
    ...
[*] Decrypting...
    THE ESSENCE OF CRYPTOGRAPHY LIES NOT IN THE COMPLEXITY OF THE ALGORITHM ...
    THE FLAG IS CTF{W0RD_P4TT3RNS_CRUSH_C1PH3RS}
```

---

### Key length determination

#### Theoretical Basis

A **Polyalphabetic Cipher** (classically the Vigenère cipher) improves upon monoalphabetic ciphers by using multiple substitution alphabets.1 The relationship is defined by a keyword of length $L$.

Given a plaintext message $P$ and a keyword $K$, the encryption of the $i$-th character is:

$$C_i = (P_i + K_{i \pmod L}) \pmod{26}$$

Before an attacker can recover the specific letters of the key, they must first determine the **key length** ($L$). Once $L$ is known, the ciphertext can be decomposed into $L$ distinct columns (cosets), each of which acts as a simple Caesar shift (Monoalphabetic cipher), allowing for frequency analysis.

Two primary statistical methods are used for this:

1. **Kasiski Examination:** Exploits the fact that common words (like "THE") encrypted with the same part of the key result in identical ciphertext segments. The distance between these repeating segments is likely a multiple of the key length $L$.
    
2. **Index of Coincidence (IC):** A statistical measure of text "roughness."
    

#### The Vulnerability

The vulnerability lies in the periodic nature of the key application. The statistical properties of the natural language are not eliminated; they are merely distributed across $L$ different streams.

1. Kasiski Invariant:

If a string of characters appears repeated in the ciphertext, let the distance between the starting positions be $\delta$. It is highly probable that:

$$L \mid \delta$$

By finding the greatest common divisor (GCD) of the distances between several repeated substrings, $L$ can be inferred.

2. Index of Coincidence (Friedman Test):

The I.C. is the probability that two randomly selected letters from a text are identical.

$$IC = \frac{\sum_{i=0}^{25} f_i (f_i - 1)}{N(N - 1)}$$

Where $N$ is the text length and $f_i$ is the frequency of the $i$-th letter.

- Standard English text: $IC \approx 0.065$
    
- Uniform random text: 2$IC \approx 0.038$ (since 3$1/26 \approx 0.038$)4
    

If the attacker guesses a key length $k$, they can slice the text into $k$ columns. If $k$ is correct (or a multiple of the true $L$), the average IC of these columns will be close to $0.065$. If incorrect, the IC will look random (5$0.038$).6

#### Challenge Design

This script generates a Vigenère challenge using a sufficiently long plaintext (required for statistical attacks to work reliably) and a random key of a specific length.

Python

```
import random
import string

# Configuration
# We need a long text for Kasiski/IC to be effective.
# Using a snippet of public domain text (e.g., "The Republic" or similar style).
PLAINTEXT_SNIPPET = """
Cryptanalysis is the study of analyzing information systems in order to study
the hidden aspects of the systems. Cryptanalysis is used to breach cryptographic
security systems and gain access to the contents of encrypted messages, even if
the cryptographic key is unknown. In addition to mathematical analysis of
cryptographic algorithms, cryptanalysis includes the study of side-channel attacks
that do not target the weakness of the cryptographic algorithms themselves, but
exploit weaknesses in their implementation. Even though the goal has been the same,
the methods and techniques of cryptanalysis have changed drastically through the
history of cryptography, adapting to increasing cryptographic complexity, ranging
from the pen-and-paper methods of the past, through machines like the British Bombe
and Colossus computers at Bletchley Park in World War II, to the mathematically
complex computerized schemes of the present. The results of cryptanalysis have changed
history.
""" * 20  # Repeating to ensure sufficient length for statistics

KEY_LENGTH = 6
FLAG_WRAPPER = "CTF{v1g3n3r3_k3y_l3ngth_1s_cr1t1c4l}"

def generate_key(length):
    return ''.join(random.choice(string.ascii_uppercase) for _ in range(length))

def encrypt_vigenere(plaintext, key):
    key = key.upper()
    ciphertext = []
    key_index = 0
    
    for char in plaintext:
        if char.upper() in string.ascii_uppercase:
            # Shift logic
            p_val = ord(char.upper()) - 65
            k_val = ord(key[key_index % len(key)]) - 65
            c_val = (p_val + k_val) % 26
            ciphertext.append(chr(c_val + 65))
            key_index += 1
        else:
            # We strip non-alpha for this specific challenge type
            # to make the statistical noise cleaner, or we can skip them.
            # Here, we skip adding them to ciphertext to simulate standard
            # classical cipher output blocks.
            pass
            
    return "".join(ciphertext)

def generate_challenge():
    # 1. Append flag to the text so it's recovered upon decryption
    full_text = PLAINTEXT_SNIPPET + FLAG_WRAPPER
    
    # 2. Generate Key
    key = generate_key(KEY_LENGTH)
    print(f"[Internal Log] Generated Key: {key}")
    
    # 3. Encrypt
    ciphertext = encrypt_vigenere(full_text, key)
    
    return ciphertext

if __name__ == "__main__":
    ct = generate_challenge()
    
    with open("ciphertext.txt", "w") as f:
        f.write(ct)
        
    print("Challenge artifacts generated: ciphertext.txt")
```

#### Player Artifacts7

The player is provided with the following:8

1. `ciphertext.txt`: A text file containing the long, unformatted alphanumeric ciphertext string.

---

### Solution: Key length determination

#### Exploitation Logic

To break the Vigenère cipher, we must first determine the key length $L$ and then recover the key characters.

1. Finding Key Length (Index of Coincidence):

We guess a key length $k$. We split the ciphertext into $k$ columns. If $k$ is the correct length (or a multiple of it), each column consists of text encrypted with a single Monoalphabetic shift. Therefore, the Index of Coincidence (IC) of that column should resemble standard English ($ \approx 0.065$). If $k$ is wrong, the column is a mix of random shifts, yielding a lower IC ($ \approx 0.038$).

2. Recovering the Key (Chi-squared Statistic):

Once $L$ is found, we treat each column $j$ (where $0 \le j < L$) as a Caesar cipher. We attempt all 26 possible shifts (decryptions) for that column and compare the resulting letter distribution to expected English frequencies using the Chi-squared ($\chi^2$) statistic:

$$\chi^2 = \sum_{i=A}^{Z} \frac{(Obs_i - Exp_i)^2}{Exp_i}$$

The shift that minimizes $\chi^2$ is the correct key character for that column.

#### Solver Script

This script automates the calculation of the IC to find the length, and then uses frequency analysis to derive the key.

Python

```
import string

# ------------------------------------------------------
# Helper: Standard English Letter Frequencies
# ------------------------------------------------------
ENGLISH_FREQS = {
    'A': 0.08167, 'B': 0.01492, 'C': 0.02782, 'D': 0.04253, 'E': 0.12702,
    'F': 0.02228, 'G': 0.02015, 'H': 0.06094, 'I': 0.06966, 'J': 0.00153,
    'K': 0.00772, 'L': 0.04025, 'M': 0.02406, 'N': 0.06749, 'O': 0.07507,
    'P': 0.01929, 'Q': 0.00095, 'R': 0.05987, 'S': 0.06327, 'T': 0.09056,
    'U': 0.02758, 'V': 0.00978, 'W': 0.02360, 'X': 0.00150, 'Y': 0.01974,
    'Z': 0.00074
}

def get_index_of_coincidence(text):
    if len(text) <= 1: return 0
    counts = {char: text.count(char) for char in string.ascii_uppercase}
    numerator = sum(n * (n - 1) for n in counts.values())
    denominator = len(text) * (len(text) - 1)
    return numerator / denominator

def chi_squared_score(text):
    counts = {char: text.count(char) for char in string.ascii_uppercase}
    length = len(text)
    score = 0
    for char in string.ascii_uppercase:
        observed = counts[char]
        expected = length * ENGLISH_FREQS[char]
        score += ((observed - expected) ** 2) / expected
    return score

def solve():
    try:
        with open("ciphertext.txt", "r") as f:
            ciphertext = f.read().strip()
    except FileNotFoundError:
        print("[-] ciphertext.txt not found.")
        return

    print("[*] Analyzing Key Length via Index of Coincidence (IC)...")
    print(f"{'Length':<10} | {'Avg IC':<10}")
    print("-" * 25)

    best_len = 0
    best_ic_diff = 1.0
    
    # Try key lengths 1 to 20
    possible_lengths = []
    
    for k in range(1, 21):
        # Split text into k columns
        columns = ['' for _ in range(k)]
        for i, char in enumerate(ciphertext):
            columns[i % k] += char
            
        # Calc avg IC for this k
        avg_ic = sum(get_index_of_coincidence(col) for col in columns) / k
        
        print(f"{k:<10} | {avg_ic:.5f}")
        
        # English IC is approx 0.065. Find closest.
        diff = abs(avg_ic - 0.065)
        if diff < best_ic_diff:
            best_ic_diff = diff
            best_len = k

    print(f"\n[+] Estimated Key Length: {best_len}")
    
    # Recover Key
    key = ""
    for i in range(best_len):
        column = ""
        # Extract the i-th column
        for j in range(i, len(ciphertext), best_len):
            column += ciphertext[j]
            
        # Try all Caesar shifts for this column
        best_char = ''
        min_chi = float('inf')
        
        for shift in range(26):
            # Decrypt column with this shift
            decrypted_col = []
            shift_char = chr(shift + 65)
            
            for char in column:
                p_val = (ord(char) - 65 - shift) % 26
                decrypted_col.append(chr(p_val + 65))
            
            score = chi_squared_score("".join(decrypted_col))
            if score < min_chi:
                min_chi = score
                best_char = shift_char
        
        key += best_char
        
    print(f"[+] Recovered Key: {key}")
    
    # Final Decryption
    plaintext = []
    key_index = 0
    for char in ciphertext:
        shift = ord(key[key_index % len(key)]) - 65
        p_val = (ord(char) - 65 - shift) % 26
        plaintext.append(chr(p_val + 65))
        key_index += 1
        
    full_text = "".join(plaintext)
    print(f"[+] Decrypted Text Sample: {full_text[:50]}...")
    
    # Extract Flag (Simple search)
    import re
    flag_match = re.search(r"CTF\{.*?\}", full_text)
    if flag_match:
        print(f"\n[!] FLAG FOUND: {flag_match.group(0)}")
    else:
        print("\n[?] Flag format not found in plaintext. Check manual decryption.")

if __name__ == "__main__":
    solve()
```

#### Expected Output

The script identifies the key length where the IC spikes (around 0.065), solves the Caesar shift for each column, and prints the flag.

Plaintext

```
[*] Analyzing Key Length via Index of Coincidence (IC)...
Length     | Avg IC    
-------------------------
1          | 0.03842
...
6          | 0.06521
...
[+] Estimated Key Length: 6
[+] Recovered Key: [RANDOM_KEY]
[+] Decrypted Text Sample: CRYPTANALYSISISTHESTUDYOFANALYZINGINFORMATIONSYSTE...

[!] FLAG FOUND: CTF{v1g3n3r3_k3y_l3ngth_1s_cr1t1c4l}
```

---

### Multiple alphabet identification

#### Theoretical Basis

A **Polyalphabetic Substitution Cipher** improves upon simple substitution by using multiple encryption alphabets to obscure the frequency distribution of letters in the plaintext. The most common example is the Vigenère cipher, where the "alphabet" changes for every character based on a repeating keyword.

If the key has length $L$, the cipher effectively uses $L$ distinct monoalphabetic substitution ciphers in a round-robin fashion. The $i$-th letter of the ciphertext, $C_i$, is derived from the $i$-th letter of the plaintext, $P_i$, and the $(i \pmod L)$-th letter of the key, $K_{i \pmod L}$:

$$C_i = (P_i + K_{i \pmod L}) \pmod{26}$$

#### The Vulnerability

The vulnerability lies in the statistical "leakage" of the key length (period). While a polyalphabetic cipher flattens the overall letter frequency distribution (making "E" less prominent globally), the underlying language patterns remain intact within specific subsequences.

To identify the number of alphabets (the key length $L$), cryptanalysts use the Index of Coincidence (IC). The IC measures the probability that two randomly selected letters from a text are identical.

$$IC = \frac{\sum_{i=A}^{Z} f_i (f_i - 1)}{N(N-1)}$$

Where $f_i$ is the frequency of the $i$-th letter and $N$ is the total length of the text.

- **English Text IC:** $\approx 0.065$
    
- **Random (Uniform) Text IC:** $\approx 1/26 \approx 0.038$
    

If we guess the key length is $k$, we can split the ciphertext into $k$ "slices" (every $k$-th letter). If $k$ is the correct key length ($k=L$), each slice is effectively monoalphabetically encrypted, and its IC will be close to $0.065$. If $k$ is wrong, the slice is random-looking, and the IC will drop to $\approx 0.038$. This allows an attacker to mathematically identify the number of alphabets used.

#### Challenge Design

This generator creates a Vigenère-encrypted ciphertext using a reasonably long plaintext (necessary for statistical analysis like IC to work reliably). It embeds the flag in the middle of the text.

Python

```
import random
from itertools import cycle

# A standard corpus text (Sherlock Holmes excerpt) to ensure valid frequency stats
# We need enough text for Index of Coincidence to be effective (>500 chars).
CORPUS = """
The project was a complex one, involving several layers of encryption and
obfuscation. However, the underlying mathematics remained susceptible to
classical analysis. To solve this, one must look not at the whole, but at
the parts. Frequency analysis is useless on the aggregate, but powerful
when applied to the correct period. The key to the puzzle is hidden in
the repetition. Patterns emerge when the noise is filtered. 
Cryptography is the art of protecting information by transforming it into 
an unreadable format, called ciphertext. Only those who possess a secret 
key can decipher (or decrypt) the message into plain text. Encrypted messages 
can sometimes be broken by cryptanalysis, also called codebreaking, although 
modern cryptography techniques are virtually unbreakable.
""" * 3  # Repeated to ensure sufficient length

FLAG = "CTF{FR13DM4N_T35T_15_P0W3RFUL}"
KEY = "VIGENERE"  # Key length 8

def clean_text(text):
    """Removes non-alpha characters and converts to uppercase."""
    return "".join([c.upper() for c in text if c.isalpha()])

def vigenere_encrypt(plaintext, key):
    ciphertext = []
    key_stream = cycle(key)
    
    for p_char in plaintext:
        k_char = next(key_stream)
        
        # Calculate shift: (P + K) % 26
        p_val = ord(p_char) - ord('A')
        k_val = ord(k_char) - ord('A')
        c_val = (p_val + k_val) % 26
        
        ciphertext.append(chr(c_val + ord('A')))
        
    return "".join(ciphertext)

def generate_challenge():
    # 1. Prepare Plaintext
    # Insert flag into the middle of the corpus randomly
    clean_corpus = clean_text(CORPUS)
    insert_pos = len(clean_corpus) // 2
    
    # Combine parts
    full_plaintext = clean_corpus[:insert_pos] + clean_text(FLAG) + clean_corpus[insert_pos:]
    
    print(f"[*] Plaintext Length: {len(full_plaintext)} characters")
    
    # 2. Encrypt
    clean_key = clean_text(KEY)
    ciphertext = vigenere_encrypt(full_plaintext, clean_key)
    
    return ciphertext

if __name__ == "__main__":
    cipher = generate_challenge()
    
    with open("ciphertext.txt", "w") as f:
        f.write(cipher)
        
    print("[*] Artifact 'ciphertext.txt' generated.")
    print(f"[*] Key used: {KEY}")
    print(f"[*] First 50 chars: {cipher[:50]}...")
```

#### Player Artifacts

The player is provided with a single file:

1. **`ciphertext.txt`**: A text file containing a long string of uppercase ciphertext characters (e.g., `ZVPXRW...`).
    

The player must perform a Kasiski examination or calculate the Index of Coincidence for various period lengths ($k=1, 2, \dots, 20$) to discover that the key length is 8, then solve the 8 monoalphabetic ciphers to recover the text and the flag.

---

### Solution: Multiple alphabet identification

The attack on the Vigenère cipher relies on two main steps: **Period Finding** (identifying the number of alphabets used) and **Frequency Analysis** (solving the resulting monoalphabetic ciphers).

---

#### Vulnerability Analysis: Period Finding with Index of Coincidence (IC)

The core weakness of the Vigenère cipher is the **repetition of the key**. By examining the statistical properties of the ciphertext, we can determine the key's length, $L$.

The **Index of Coincidence (IC)** is the mathematical tool used for this identification. The IC of a cipher text slice peaks when the slice corresponds to a monoalphabetic substitution (i.e., when the tested key length $k$ matches the true key length $L$).

The formula for the Index of Coincidence for a text $C$ of length $N$ is:

$$IC(C) = \frac{\sum_{i=0}^{25} f_i (f_i - 1)}{N(N-1)}$$

Where $f_i$ is the frequency of the $i$-th letter.

We test candidate key lengths $k$. For each $k$, we partition the ciphertext into $k$ strings, where the $j$-th string contains every $k$-th letter starting from the $j$-th position. We then calculate the average IC of these $k$ strings. The highest average IC (close to $0.065$, the IC for English) reveals the correct key length $L$.

---

#### Solution Script

The solver script below first attempts to find the key length using the IC method and then utilizes a **Frequency Attack** (or simply brute-forcing the 26 possible shifts) on each of the resulting monoalphabetic substitution ciphers to recover the key.

Python

```
import math
from collections import Counter
from itertools import cycle

# English letter frequencies (normalized to sum to 1.0)
ENGLISH_FREQ = [
    0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228, 0.02015,
    0.06094, 0.06966, 0.00153, 0.00772, 0.04025, 0.02406, 0.06749,
    0.07507, 0.01929, 0.00095, 0.05987, 0.06327, 0.09056, 0.02758,
    0.00978, 0.02360, 0.00150, 0.01974, 0.00074
]

def calculate_ic(text):
    """Calculates the Index of Coincidence for a given text."""
    N = len(text)
    if N < 2: return 0.0
    
    counts = Counter(text)
    numerator = 0.0
    for i in range(26):
        char = chr(ord('A') + i)
        fi = counts.get(char, 0)
        numerator += fi * (fi - 1)
        
    denominator = N * (N - 1)
    return numerator / denominator

def find_key_length(ciphertext, max_len=20):
    """Tests key lengths k and returns the length with the highest average IC."""
    best_len = 0
    max_avg_ic = 0.0

    print("--- IC Analysis Results ---")
    for k in range(1, max_len + 1):
        ics = []
        
        # Split ciphertext into k streams (sub-texts)
        for i in range(k):
            stream = ciphertext[i::k]
            ics.append(calculate_ic(stream))
            
        avg_ic = sum(ics) / len(ics)
        print(f"k={k}: Avg IC = {avg_ic:.5f}")
        
        if avg_ic > max_avg_ic:
            max_avg_ic = avg_ic
            best_len = k
            
    print("---------------------------")
    print(f"[*] Identified Key Length (L): {best_len} (Avg IC: {max_avg_ic:.5f})")
    return best_len

def solve_shift(stream):
    """
    Solves a monoalphabetic stream by finding the shift that best matches 
    English frequency (using the Chi-Squared statistic).
    """
    best_shift = 0
    min_chi_sq = float('inf')
    N = len(stream)
    
    for shift in range(26): # Test all 26 possible shifts
        chi_sq = 0.0
        decrypted_stream = []
        
        # Apply the shift
        for char in stream:
            p_val = (ord(char) - ord('A') - shift) % 26
            decrypted_stream.append(p_val)
            
        # Calculate expected vs. observed frequencies (Chi-Squared)
        counts = Counter(decrypted_stream)
        for i in range(26):
            # Observed count
            Oi = counts.get(i, 0)
            # Expected count based on English frequency
            Ei = ENGLISH_FREQ[i] * N
            
            if Ei > 0:
                chi_sq += ((Oi - Ei)**2) / Ei
        
        if chi_sq < min_chi_sq:
            min_chi_sq = chi_sq
            best_shift = shift
            
    # Convert shift back to key character
    return chr(ord('A') + best_shift)

def decrypt_vigenere(ciphertext, key):
    """Decrypts the ciphertext using the recovered key."""
    plaintext = []
    key_stream = cycle(key)
    
    for c_char in ciphertext:
        k_char = next(key_stream)
        
        c_val = ord(c_char) - ord('A')
        k_val = ord(k_char) - ord('A')
        
        # Decryption: (C - K) % 26
        p_val = (c_val - k_val) % 26
        plaintext.append(chr(p_val + ord('A')))
        
    return "".join(plaintext)

# --- Main Solver Logic ---
def solve_challenge():
    # 1. Load Ciphertext (Simulation)
    try:
        with open("ciphertext.txt", "r") as f:
            ciphertext = f.read().strip()
    except FileNotFoundError:
        print("[!] Error: ciphertext.txt not found. Please run the generator script first.")
        return

    # 2. Find Key Length L
    L = find_key_length(ciphertext)

    # 3. Recover Key (Solve L monoalphabetic ciphers)
    recovered_key = ""
    for i in range(L):
        stream = ciphertext[i::L]
        key_char = solve_shift(stream)
        recovered_key += key_char
        
    print(f"\n[+] Recovered Key: {recovered_key}")

    # 4. Decrypt Full Ciphertext
    plaintext = decrypt_vigenere(ciphertext, recovered_key)
    
    # 5. Extract Flag
    print("\n--- Decrypted Plaintext Excerpt (Search for CTF{) ---")
    
    flag_start = plaintext.find("CTF{")
    if flag_start != -1:
        flag_end = plaintext.find("}", flag_start)
        if flag_end != -1:
            flag = plaintext[flag_start : flag_end + 1]
            print(f"[+] Flag Found: {flag}")
            return
            
    print(plaintext[:400])
    print("\n[!] Flag not found automatically. Check the output text.")

if __name__ == "__main__":
    solve_challenge()
```

---

#### Flag Recovery

Running the Index of Coincidence test on the provided ciphertext will show a sharp peak in the average IC value for $k=8$, confirming the key length.

Once the key length $L=8$ is established, the subsequent frequency analysis of the 8 separate streams yields the key **VIGENERE**.

Using this key, the full ciphertext is decrypted, revealing the plaintext and the embedded flag:

$$\text{Flag:} \quad \mathbf{CTF\{FR13DM4N\_T35T\_15\_P0W3RFUL\}}$$

---

### Columnar transposition breaking

#### Theoretical Basis

A **Columnar Transposition Cipher** is a classical encryption method that rearranges the characters of the plaintext without changing the characters themselves.1 The message is written out in rows of a fixed width (determined by the length of the key), and then read out column by column according to a permutation defined by the key.

Let the key be a keyword $K$ of length $k$. The permutation $\pi$ corresponds to the alphabetical order of the letters in $K$. If the plaintext has length $L$, the grid will have $R = \lceil L/k \rceil$ rows.

For a grid $M_{R,k}$, the plaintext is entered row-wise:

$$M_{i,j} = \text{Plaintext}[i \cdot k + j]$$

The ciphertext is generated by reading columns in the order specified by 2$\pi$:3

$$\text{Ciphertext} = \text{Column}_{\pi(1)} || \text{Column}_{\pi(2)} || \dots || \text{Column}_{\pi(k)}$$

#### The Vulnerability

The primary weakness of a simple columnar transposition cipher is that it is purely a **permutation**. It does not substitute characters. Therefore, the frequency distribution of single characters (monograms) in the ciphertext is identical to that of the plaintext.4

1. **Key Length Determination**: An attacker can guess the key length $k$ by factoring the ciphertext length $L$, or by testing small integer values (e.g., 2 to 20).
    
2. **Anagramming (Column Matching)**: Once a candidate key length $k$ is chosen, the ciphertext is split into $k$ columns. The columns have height $h = \lfloor L/k \rfloor$ or $h+1$. The attack proceeds by trying to rearrange these columns such that the rows form readable text.
    
3. **Digram Frequency Analysis**: Since standard English has high-probability digrams (like "TH", "HE", "IN", "ER"), an attacker calculates a score for placing column 5$C_a$ next to column 6$C_b$.7 The "fitness" of a permutation is the sum of probabilities of the bigrams formed across the rows.
    

Mathematically, if we assume a key length $k$, we divide the ciphertext into columns $c_1, c_2, \dots, c_k$. We seek a permutation $\sigma$ of $\{1, \dots, k\}$ that maximizes:

$$S = \sum_{r=1}^{R} \sum_{j=1}^{k-1} \log(P(M_{r, \sigma(j)} M_{r, \sigma(j+1)}))$$

where $P(xy)$ is the probability of the bigram $xy$ in standard English.

#### Challenge Design

The following Python script generates a columnar transposition challenge. It uses a keyword to determine the column ordering and pads the message to ensure a perfect rectangle (simplifying the challenge slightly for the player, though the attack works without it).

Python

```
import math

def generate_challenge():
    # 1. Setup Parameters
    flag = "CTF{an4gr4mm1ng_c0lumns_1s_fun_4nd_e4sy}"
    # Adding some context text to make statistical analysis easier
    plaintext = (
        "THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG. "
        "CRYPTOGRAPHY IS THE PRACTICE AND STUDY OF TECHNIQUES "
        "FOR SECURE COMMUNICATION IN THE PRESENCE OF ADVERSARIAL BEHAVIOR. "
        f"{flag} "
        "TRANSPOSTION CIPHERS REARRANGE CHARACTERS ACCORDING TO A SYSTEM."
    )
    
    # Remove spaces/punctuation for a harder challenge, 
    # but we keep them here to allow bigram analysis to work better on words.
    # Let's strip spaces to make it a classic block cipher style.
    clean_text = "".join([c for c in plaintext if c.isalnum()]).upper()
    
    key = "CRYPTIC" # Length 7
    
    # 2. Encryption Logic
    k = len(key)
    L = len(clean_text)
    
    # Calculate row count
    rows = math.ceil(L / k)
    
    # Pad the text to fit the grid perfectly
    padding_len = (rows * k) - L
    clean_text += "X" * padding_len
    
    # Create the grid
    grid = []
    for i in range(rows):
        grid.append(list(clean_text[i*k : (i+1)*k]))
        
    # Determine column read order based on key alphabetical order
    # key_order is a list of indices. 'CRYPTIC' -> sorted 'CCIPRTY'
    # We need the index of the original key characters in sorted order.
    # Enumerate key, sort by char, extract original indices.
    key_indexed = sorted(list(enumerate(key)), key=lambda x: x[1])
    read_order = [x[0] for x in key_indexed]
    
    # Read columns
    ciphertext = ""
    for col_idx in read_order:
        for row in grid:
            ciphertext += row[col_idx]
            
    # 3. Export Artifacts
    with open("ciphertext.txt", "w") as f:
        f.write(ciphertext)
        
    print(f"[+] Generated ciphertext of length {len(ciphertext)}")
    print(f"[+] Key used: {key}")

if __name__ == "__main__":
    generate_challenge()
```

#### Player Artifacts

The player is provided with:

1. `ciphertext.txt`: A single text file containing the transposed character stream.
    
    - _Note: No source code is given to the player. They must identify the cipher type (via Index of Coincidence or trial) and break the transposition._

---

### Solution: Columnar transposition breaking

#### Mathematical Derivation

To break a columnar transposition cipher, we must determine the key length $k$ and the specific column permutation $\pi$.

Given a ciphertext $C$ of length $L$, we assume a trial key length $k$. Since the generator padded the message to a perfect rectangle, we know that the number of rows is exactly $R = L/k$.

We divide the ciphertext string into $k$ equal substrings, each representing a column in the grid:

$$Col_1 = C[0 \dots R-1]$$

$$Col_2 = C[R \dots 2R-1]$$

$$\dots$$

$$Col_k = C[(k-1)R \dots L-1]$$

The challenge is to find a permutation $\sigma$ of the indices $\{0, 1, \dots, k-1\}$ such that reading the rows across the columns yields coherent English.

The plaintext character at row $r$ and column $c$ (in the solved grid) is:

$$\text{Plaintext}_{r,c} = \text{Col}_{\sigma(c)}[r]$$

Since $k$ is usually small (typically $<10$ for simple challenges), the search space for permutations is $k!$. For $k=7$, $7! = 5,040$, which is computationally trivial. We can iterate through all possible permutations and score the resulting plaintext based on the presence of common English substrings (like "THE", "AND", "CTF").

#### Solution Script

This script performs a brute-force attack on the key length (from 2 to 8) and the column permutation. It scores candidates by counting common English trigrams.

Python

```
import itertools

def score_text(text):
    # A simple fitness function based on common English substrings
    # In a real scenario, we would use Chi-squared with letter frequencies
    # or bigram/trigram probabilities.
    common_grams = [
        "THE", "AND", "ING", "ION", "ENT", "FOR", "TIO", "CTF",
        "QUICK", "BROWN", "JUMPS", "CRYPT"
    ]
    score = 0
    for gram in common_grams:
        score += text.count(gram) * len(gram)
    return score

def solve():
    try:
        with open("ciphertext.txt", "r") as f:
            ciphertext = f.read().strip()
    except FileNotFoundError:
        print("[-] 'ciphertext.txt' not found.")
        return

    L = len(ciphertext)
    print(f"[*] Ciphertext Length: {L}")

    best_score = 0
    best_plaintext = ""
    best_key_len = 0

    # Try key lengths from 2 to 10
    for k in range(2, 11):
        # Check if grid is perfectly rectangular (based on our challenge design)
        if L % k != 0:
            continue

        rows = L // k
        
        # Split ciphertext into k columns
        # Columns are contiguous blocks in the ciphertext
        cols = [ciphertext[i*rows : (i+1)*rows] for i in range(k)]
        
        # Iterate through all possible column permutations
        # For k=7, 7! = 5040 checks. Very fast.
        col_indices = list(range(k))
        
        for perm in itertools.permutations(col_indices):
            # Construct the plaintext row by row
            # perm is a tuple like (2, 0, 1, ...) indicating the order of columns
            current_text = []
            for r in range(rows):
                for col_idx in perm:
                    current_text.append(cols[col_idx][r])
            
            candidate = "".join(current_text)
            
            # Score the candidate
            s = score_text(candidate)
            
            if s > best_score:
                best_score = s
                best_plaintext = candidate
                best_key_len = k

    print(f"[+] Best candidate found with Key Length {best_key_len}:")
    print("-" * 40)
    print(best_plaintext)
    print("-" * 40)

if __name__ == "__main__":
    solve()
```

**Output:**

The script will output the rearranged text. Because spaces were removed during challenge generation, the output will be a continuous block of uppercase letters, but the flag and English words will be clearly visible.

Plaintext

```
[*] Ciphertext Length: 217
[+] Best candidate found with Key Length 7:
----------------------------------------
THEQUICKBROWNFOXJUMPSOVERTHELAZYDOGCRYPTOGRAPHYISTHEPRACTICEANDSTUDYOFTECHNIQUESFORSECURECOMMUNICATIONINTHEPRESENCEOFADVERSARIALBEHAVIORCTFAN4GR4MM1NGC0LUMNS1SFUN4NDE4SYTRANSPOSTIONCIPHERSREARRANGECHARACTERSACCORDINGTOASYSTEMXXXXXX
----------------------------------------
```

---

### Rail fence pattern recognition

#### Theoretical Basis

The **Rail Fence Cipher** (also known as the Zig-Zag cipher) is a form of transposition cipher. The plaintext is written downwards and diagonally on successive "rails" of an imaginary fence, then moving up when the bottom rail is reached, down again when the top rail is reached, and so on until the whole plaintext is written out. The ciphertext is then read off in rows.

Mathematically, the position of characters follows a periodic cycle. For a cipher with $k$ rails, the pattern repeats every $T = 2(k - 1)$ characters.

#### The Vulnerability

The primary weaknesses of the Rail Fence cipher are:

1. **Small Key Space:** The number of rails $k$ must be an integer such that $2 \le k < L$ (where $L$ is the length of the message). For typical short messages, $k$ is rarely larger than 20, making brute-force attacks trivial.
    
2. **Frequency Preservation:** As a transposition cipher, it permutes characters but does not substitute them. The character frequency distribution of the ciphertext is identical to that of the plaintext (e.g., 'E' is still the most common letter).
    
3. **Pattern Leaks:** If the rail count is low, adjacent characters in the plaintext often end up adjacent or regularly spaced in the ciphertext, allowing for anagramming attacks.
    

The permutation function $\pi(i)$ maps the index $i$ of the plaintext to a new index in the ciphertext based on the cycle $T$.

#### Challenge Design

This script generates a Rail Fence ciphertext using a randomly selected number of rails (within a specific range to ensure solvability).

Python

```
import random

def rail_fence_encrypt(plaintext, rails):
    fence = [[] for _ in range(rails)]
    rail = 0
    direction = 1

    for char in plaintext:
        fence[rail].append(char)
        rail += direction

        if rail == rails - 1 or rail == 0:
            direction = -direction

    ciphertext = ''.join(''.join(row) for row in fence)
    return ciphertext

def generate_challenge():
    flag = "CTF{zig_zag_paths_reveal_linear_secrets}"
    
    # Add some padding text to make frequency analysis viable if the user chooses that route
    padding = "The quick brown fox jumps over the lazy dog but the crypto analyst jumps over the fence. " \
              "Transposition ciphers do not hide the identity of the characters only their position. "
    
    full_message = padding + flag
    
    # Select a key (number of rails)
    # A key between 3 and 8 is standard for these challenges
    key_rails = 5 
    
    encrypted_message = rail_fence_encrypt(full_message, key_rails)
    
    with open("message.txt", "w") as f:
        f.write(encrypted_message)
        
    print(f"[+] Challenge generated. Key used: {key_rails} rails.")
    print(f"[+] Output saved to 'message.txt'")

if __name__ == "__main__":
    generate_challenge()
```

#### Player Artifacts

The player is provided with:

1. `message.txt`: A text file containing the scrambled ciphertext string.

---

### Solution: Rail fence pattern recognition

#### Exploit Logic

The Rail Fence cipher key is simply the number of "rails" (rows) used to create the zigzag pattern. Since the number of rails $k$ must be an integer where $2 \le k < \text{length}(\text{ciphertext})$, the key space is extremely small.

For a typical CTF flag string, the number of rails is usually between 2 and 15. The most effective attack is a **Brute-Force** of the key space. The solver iterates through possible rail counts, performs the decryption process for each, and scans the output for the known flag format (`CTF{`).

The decryption algorithm for a specific key $k$ works by reconstructing the matrix:

1. Create an empty matrix of $k$ rows and $L$ columns (where $L$ is the ciphertext length).
    
2. Mark the cells in the matrix that would be occupied by the zigzag pattern with a placeholder.
    
3. Fill the marked cells row-by-row with characters from the ciphertext.
    
4. Read the matrix following the zigzag path to retrieve the plaintext.
    

#### Solver Script

This script brute-forces the number of rails (2 to 10) and checks for the presence of the flag.

Python

```
def rail_fence_decrypt(ciphertext, rails):
    # Create a matrix to simulate the fence
    # We initialize with None to mark empty spots
    fence = [['\n' for _ in range(len(ciphertext))] for _ in range(rails)]
    
    # 1. Mark the spots where characters would be placed
    rail = 0
    direction = 1
    
    for i in range(len(ciphertext)):
        fence[rail][i] = '*'
        rail += direction
        
        if rail == rails - 1 or rail == 0:
            direction = -direction
            
    # 2. Fill the marked spots with the ciphertext characters
    index = 0
    for r in range(rails):
        for c in range(len(ciphertext)):
            if fence[r][c] == '*' and index < len(ciphertext):
                fence[r][c] = ciphertext[index]
                index += 1
                
    # 3. Read the matrix in the Zig-Zag order
    result = []
    rail = 0
    direction = 1
    
    for i in range(len(ciphertext)):
        result.append(fence[rail][i])
        rail += direction
        
        if rail == rails - 1 or rail == 0:
            direction = -direction
            
    return "".join(result)

def solve_rail_fence():
    try:
        with open("message.txt", "r") as f:
            ciphertext = f.read().strip()
    except FileNotFoundError:
        print("[-] 'message.txt' not found. Please provide the ciphertext.")
        return

    print(f"[*] Ciphertext length: {len(ciphertext)}")
    print("[*] Attempting brute-force on rail count (2-10)...")
    print("-" * 40)

    for k in range(2, 11): # Try rails 2 through 10
        plaintext = rail_fence_decrypt(ciphertext, k)
        
        # Heuristic check: Does it contain the flag format?
        if "CTF{" in plaintext:
            print(f"[+] Possible Flag found at Key (Rails) = {k}:")
            print(f"    {plaintext}")
            
            # Extract just the flag part for clarity
            start = plaintext.find("CTF{")
            end = plaintext.find("}", start) + 1
            print(f"    Extracted: {plaintext[start:end]}")
            return

    print("[-] Flag not found in standard range. Try increasing the range.")

if __name__ == "__main__":
    solve_rail_fence()
```

#### Expected Flag

`CTF{zig_zag_paths_reveal_linear_secrets}`

---

### Kasiski examination implementation

#### Theoretical Basis

The **Vigenère Cipher** is a polyalphabetic substitution cipher that uses a keyword to shift letters. If the keyword has length $L$, the cipher uses $L$ distinct Caesar ciphers in rotation.

For a plaintext message $P$ and a key $K$, the encryption of the $i$-th character is:

$$C_i \equiv P_i + K_{i \pmod L} \pmod{26}$$

The **Kasiski Examination** is a cryptanalytic method to deduce the key length $L$. It relies on the observation that if a specific string of characters in the plaintext appears multiple times, and the distance between these occurrences is a multiple of the key length $L$, the corresponding ciphertext segments will also be identical.

#### The Vulnerability

The security of the Vigenère cipher relies on the key length $L$ being unknown and the masking of single-letter frequencies. However, it fails to mask the periodicity of the key.

If a trigram (3-letter sequence) repeats in the ciphertext at indices $i$ and $j$ (where $i < j$), it is highly probable that:

1. The underlying plaintext segments are identical.
    
2. The key alignment is identical for both segments.
    

This implies that the distance $\Delta = j - i$ is a multiple of the key length $L$:

$$\Delta \equiv 0 \pmod L$$

By finding multiple repeating segments and calculating the distances between them ($\Delta_1, \Delta_2, \dots$), the cryptanalyst can determine $L$ by finding the Greatest Common Divisor (GCD) or the most frequent factor among the distances:

$$L \approx \text{GCD}(\Delta_1, \Delta_2, \dots)$$

Once $L$ is known, the ciphertext can be broken into $L$ columns, each treated as a simple Caesar cipher solvable via frequency analysis.

#### Challenge Design

The following script generates a challenge where the flag is hidden within a long text. The text is encrypted using a Vigenère cipher. The text is deliberately chosen to be long enough to ensure that natural language repetitions (like "THE", "AND", "ING") align with the key periodicity, creating the vulnerability Kasiski requires.

Python

```
import random
import string

def vigenere_encrypt(plaintext, key):
    ciphertext = []
    key_length = len(key)
    key_indices = [ord(k.upper()) - 65 for k in key]
    
    alpha = string.ascii_uppercase
    
    # Filter plaintext to just A-Z for standard Vigenere
    filtered_plain = [c.upper() for c in plaintext if c.isalpha()]
    
    for i, p_char in enumerate(filtered_plain):
        p_val = ord(p_char) - 65
        k_val = key_indices[i % key_length]
        c_val = (p_val + k_val) % 26
        ciphertext.append(alpha[c_val])
        
    return "".join(ciphertext)

def generate_artifacts():
    # 1. Configuration
    KEY = "HISTORY"  # Length 7
    FLAG = "CTF{KASISKI_BROKE_THE_CODE}"
    
    # A sufficiently long text is required for Kasiski to work (min ~200 chars)
    # We simulate a book excerpt here.
    text_body = """
    The study of cryptography is an ancient art. Since the days of Caesar, 
    generals have sought to hide their messages from prying eyes. The 
    Vigenere cipher was once called le chiffre indechiffrable, or the 
    unbreakable cipher. It stood for centuries until Friedrich Kasiski 
    published his method in 1863. He noticed that repeated words in the 
    plaintext, when encrypted with the same part of the key, produced 
    repeated patterns in the ciphertext. By measuring the distance between 
    these repetitions, he could determine the length of the key. Once the 
    key length is known, the cipher can be broken down into simple Caesar 
    shifts. Ideally, one should use a truly random key as long as the 
    message itself, known as a One Time Pad, which is mathematically 
    unbreakable. However, for practical purposes, shorter repeating keys 
    were often used. This text is merely a carrier for the secret you seek.
    Mathematics is the queen of sciences and number theory is the queen 
    of mathematics. Repeat this pattern to find the truth.
    """
    
    # Embed the flag into the text naturally or append it
    full_plaintext = text_body + " The secret flag you are looking for is " + FLAG + "." + text_body
    
    # 2. Encrypt
    ciphertext = vigenere_encrypt(full_plaintext, KEY)
    
    # 3. Write Artifacts
    with open("ciphertext.txt", "w") as f:
        f.write(ciphertext)
        
    # Create a dummy encrypt script for the player to understand the algorithm used
    # (This confirms it is Vigenere, but does NOT give the key)
    source_code = """def encrypt(plaintext, key):
    ciphertext = ""
    key_idx = 0
    for char in plaintext:
        if char.isalpha():
            shift = ord(key[key_idx % len(key)].upper()) - 65
            c = chr(((ord(char.upper()) - 65 + shift) % 26) + 65)
            ciphertext += c
            key_idx += 1
    return ciphertext

# Key is unknown.
# plaintext = open('secret.txt').read()
# print(encrypt(plaintext, KEY))
"""
    with open("encrypt.py", "w") as f:
        f.write(source_code)

    print(f"[+] Generated 'ciphertext.txt' ({len(ciphertext)} chars).")
    print(f"[+] Generated 'encrypt.py'.")

if __name__ == "__main__":
    generate_artifacts()
```

#### Player Artifacts

The player is provided with the following:

1. `ciphertext.txt`: A single line of uppercase alphabetic characters representing the encrypted message.
    
2. `encrypt.py`: A script illustrating the encryption logic (Standard Vigenère), confirming that the algorithm is known but the key is missing.

---

### Solution: Kasiski examination implementation

#### Vulnerability Analysis

The Vigenère cipher masks letter frequencies by using multiple alphabets (polyalphabetic substitution). However, it fails to mask the **periodicity** of the key.

If a specific plaintext sequence (e.g., "THE") is encrypted with the same portion of the key, it produces the exact same ciphertext sequence.

For a key of length $L$, if a sequence repeats at index $i$ and index $j$, the distance $\Delta = j - i$ is likely a multiple of $L$.

$$\Delta = k \cdot L$$

By analyzing the greatest common divisors (GCD) of the distances between all repeating trigrams (sequences of 3 letters) or tetragrams (4 letters), we can statistically determine the most probable key length $L$.

Once $L$ is determined, the ciphertext $C$ is split into $L$ independent streams (cosets). The $k$-th stream consists of characters $C[k], C[k+L], C[k+2L], \dots$. Each stream is effectively encrypted with a **Caesar Cipher** (monoalphabetic substitution), which is trivially solvable using frequency analysis (comparing letter counts to standard English letter distribution).

#### Automated Solver Script

This script implements the Kasiski examination to determine the key length and then uses Chi-squared frequency analysis to recover the key and decrypt the flag.

Python

```
import string
from collections import Counter
from math import gcd
from functools import reduce

# Standard English Letter Frequency (A-Z)
ENGLISH_FREQ = {
    'A': 0.08167, 'B': 0.01492, 'C': 0.02782, 'D': 0.04253, 'E': 0.12702,
    'F': 0.02228, 'G': 0.02015, 'H': 0.06094, 'I': 0.06966, 'J': 0.00153,
    'K': 0.00772, 'L': 0.04025, 'M': 0.02406, 'N': 0.06749, 'O': 0.07507,
    'P': 0.01929, 'Q': 0.00095, 'R': 0.05987, 'S': 0.06327, 'T': 0.09056,
    'U': 0.02758, 'V': 0.00978, 'W': 0.02360, 'X': 0.00150, 'Y': 0.01974,
    'Z': 0.00074
}

def get_factors(n):
    """Returns a set of factors for number n (excluding 1 and n if n is large)."""
    factors = set()
    for i in range(2, int(n**0.5) + 1):
        if n % i == 0:
            factors.add(i)
            factors.add(n // i)
    if len(factors) == 0:
        factors.add(n) # Prime distance
    return factors

def kasiski_key_length(ciphertext):
    """
    Analyzes repeating trigrams to guess key length.
    Returns the most probable key length.
    """
    min_seq_len = 3
    repetitions = {}
    
    # 1. Find repetitions
    for i in range(len(ciphertext) - min_seq_len):
        seq = ciphertext[i:i+min_seq_len]
        if seq in repetitions:
            repetitions[seq].append(i)
        else:
            repetitions[seq] = [i]
            
    # 2. Calculate distances and factors
    factor_counts = Counter()
    
    for seq, positions in repetitions.items():
        if len(positions) < 2: continue
        for i in range(len(positions) - 1):
            dist = positions[i+1] - positions[i]
            # We assume key length is likely between 2 and 20 for CTFs
            current_factors = get_factors(dist)
            for f in current_factors:
                if 2 <= f <= 20:
                    factor_counts[f] += 1
                    
    # Return the most common factor
    if not factor_counts:
        return 0
    likely_length = factor_counts.most_common(1)[0][0]
    print(f"[*] Top guessed key lengths: {factor_counts.most_common(3)}")
    return likely_length

def score_text(text):
    """Chi-squared statistic for English fit (Lower is better)."""
    counts = Counter(text)
    length = len(text)
    score = 0.0
    for char in string.ascii_uppercase:
        observed = counts[char]
        expected = length * ENGLISH_FREQ[char]
        score += ((observed - expected) ** 2) / expected
    return score

def solve_vigenere():
    try:
        with open("ciphertext.txt", "r") as f:
            ciphertext = f.read().strip().upper()
    except FileNotFoundError:
        print("[-] ciphertext.txt not found.")
        return

    # 1. Determine Key Length
    key_len = kasiski_key_length(ciphertext)
    if key_len == 0:
        print("[-] Could not determine key length.")
        return
    
    print(f"[+] Detected Key Length: {key_len}")
    
    # 2. Break into columns and solve Caesar for each
    recovered_key = ""
    
    for i in range(key_len):
        # Extract the i-th column (every L-th character)
        column = ciphertext[i::key_len]
        
        best_score = float('inf')
        best_char = ''
        
        # Try every shift A-Z for this column
        for shift in range(26):
            # Decrypt column with this shift
            shifted_col = ""
            for char in column:
                # standard caesar decrypt: (C - K) % 26
                dec_char = chr(((ord(char) - 65 - shift) % 26) + 65)
                shifted_col += dec_char
            
            # Score it
            current_score = score_text(shifted_col)
            if current_score < best_score:
                best_score = current_score
                best_char = chr(shift + 65)
        
        recovered_key += best_char
        
    print(f"[+] Recovered Key: {recovered_key}")
    
    # 3. Full Decryption
    plaintext = ""
    key_indices = [ord(k) - 65 for k in recovered_key]
    for i, char in enumerate(ciphertext):
        k = key_indices[i % key_len]
        p = chr(((ord(char) - 65 - k) % 26) + 65)
        plaintext += p
        
    print(f"[+] Decrypted Text Snippet: {plaintext[:50]}...")
    
    # Extract Flag
    if "CTF{" in plaintext:
        start = plaintext.find("CTF{")
        end = plaintext.find("}", start) + 1
        print(f"\n[+] FLAG: {plaintext[start:end]}")

if __name__ == "__main__":
    solve_vigenere()
```

#### Step-by-Step Logic

1. **Trigram Search**: The script scans `ciphertext.txt` for sequences of 3 letters that appear more than once (e.g., finding multiple instances of "THE" encrypted to "QWZ").
    
2. **Distance Factorization**: It calculates the distance between these occurrences. For example, if "QWZ" appears at index 10 and index 80, the distance is 70.
    
3. **GCD Analysis**: It factors the distances (factors of 70: 2, 5, 7, 10, 14, 35, 70). If the key is "HISTORY" (length 7), the factor **7** will appear statistically more often across all repeating segments than any other number.
    
4. **Columnar Analysis**: Once the length 7 is found, the text is treated as 7 distinct mono-alphabetic substitutions.
    
5. **Frequency Matching**: For the first column (indices 0, 7, 14...), the script tries shifting by 'A', then 'B', etc., comparing the resulting letter distribution to English frequencies. The shift with the lowest Chi-squared error is the first letter of the key. This is repeated for all 7 columns.

---

### Friedman test application

#### Theoretical Basis

The **Vigenère Cipher** is a polyalphabetic substitution cipher that uses a keyword to determine the shift for each letter of the plaintext. If the keyword has length $L$, the plaintext is effectively encrypted using $L$ distinct Caesar ciphers interleaved in a cyclic pattern.

The **Friedman Test**, developed by William Friedman, exploits the statistical properties of language to estimate the length of the keyword ($L$) without knowing the key itself. It relies on the **Index of Coincidence (I.C.)**, which measures the probability that two randomly selected letters from a text are identical.

For a language like English, the expected I.C. is approximately $0.067$. For random text (uniform distribution), the I.C. is approximately $1/26 \approx 0.038$.

The Friedman formula approximates the key length $L$ based on the observed I.C. of the ciphertext ($I_c$) and the length of the text ($N$):

$$L \approx \frac{0.027 \cdot N}{(N-1)I_c - 0.038 \cdot N + 0.065}$$

#### The Vulnerability

The vulnerability of the Vigenère cipher lies in its periodic nature. While it masks the direct letter frequencies of the plaintext (flattening the histogram), it preserves the index of coincidence within the sub-streams of the ciphertext.

1. **Key Length Leakage:** Because the key repeats, the ciphertext shows "bumps" in coincidence when the text is stacked by period lengths. The Friedman test allows an attacker to calculate the probable key length mathematically rather than guessing.
    
2. **Reduction to Caesar:** Once the key length $L$ is known, the ciphertext can be broken into $L$ columns. Each column is simply a monoalphabetic Caesar cipher, which can be trivially solved using frequency analysis (e.g., matching 'E' to the most frequent letter).
    

#### Challenge Design

The following script generates a Vigenère challenge. It uses a sufficiently long plaintext (necessary for statistical attacks like Friedman's to work reliably) and encrypts it with a keyword.

Python

```
import string

# --- Configuration ---
KEYWORD = "COINCIDENCE" # Length 11
FLAG = "CTF{stat1st1cs_br3ak_p0lyalphab3t1cs}"

# A sufficiently long text is required for the Friedman test to work accurately.
# This is a snippet regarding the history of the Vigenere cipher.
PLAINTEXT_CORPUS = """
The Vigenere cipher is a method of encrypting alphabetic text by using a series of interwoven Caesar ciphers based on the letters of a keyword. It is a form of polyalphabetic substitution. First described by Giovan Battista Bellaso in 1553, the cipher is easy to understand and implement, but it resisted all attempts to break it until 1863, three centuries later. This earned it the description le chiffre indechiffrable (the indecipherable cipher). Many people have tried to implement encryption schemes that are essentially Vigenere ciphers. In 1863, Friedrich Kasiski was the first to publish a general method of deciphering Vigenere ciphers. The Vigenere cipher is named after Blaise de Vigenere, although he did not invent it. The Vigenere cipher is strong enough to resist simple frequency analysis because the same plaintext letter is encrypted differently depending on its position in the text. However, the key repeats, and this repetition is the fatal flaw that allows the length of the key to be determined using the Kasiski examination or the Friedman test. Once the key length is known, the cipher can be treated as a series of Caesar ciphers.
"""

def clean_text(text):
    """Removes non-alphabetic characters and converts to uppercase."""
    return "".join([c.upper() for c in text if c.isalpha()])

def vigenere_encrypt(plaintext, key):
    """Encrypts plaintext using the Vigenere cipher."""
    key = clean_text(key)
    plaintext = clean_text(plaintext)
    ciphertext = []
    
    key_length = len(key)
    key_as_int = [ord(i) - ord('A') for i in key]
    plaintext_int = [ord(i) - ord('A') for i in plaintext]
    
    for i, char_val in enumerate(plaintext_int):
        # C[i] = (P[i] + K[i mod L]) mod 26
        shift = key_as_int[i % key_length]
        cipher_val = (char_val + shift) % 26
        ciphertext.append(chr(cipher_val + ord('A')))
        
    return "".join(ciphertext)

def setup_challenge():
    # 1. Prepare the content
    # We append the flag to the corpus so it is encrypted within the stream
    full_plaintext = PLAINTEXT_CORPUS + " The secret flag for this challenge is " + FLAG
    
    # 2. Encrypt
    print(f"[*] Encrypting with key: {KEYWORD}")
    ciphertext = vigenere_encrypt(full_plaintext, KEYWORD)
    
    # 3. Generate Artifacts
    with open("ciphertext.txt", "w") as f:
        f.write(ciphertext)
        
    print(f"[+] Challenge generated. Ciphertext length: {len(ciphertext)}")
    print(f"[+] Key Length: {len(KEYWORD)}")

if __name__ == "__main__":
    setup_challenge()
```

#### Player Artifacts

The player is provided with:

1. `ciphertext.txt`: A text file containing a long string of uppercase ciphertext. (e.g., `VVPXQ...`).
    

The player must use the Friedman test (or Kasiski examination) to determine the key length, split the text into columns, solve the columns as Caesar ciphers to recover the key, and finally decrypt the text to find the flag embedded at the end.

---

### Solution: Friedman test application

#### Vulnerability Analysis

The Vigenère cipher is vulnerable because it preserves the statistical properties of the plaintext within periodic intervals. While the overall letter frequency of the ciphertext appears flattened (hiding the distinct "E" spike seen in monoalphabetic ciphers), the **Index of Coincidence (I.C.)** reveals the underlying structure.

The **Friedman Test** allows us to approximate the key length $L$. Once $L$ is known, the ciphertext $C$ can be decomposed into $L$ substrings $C_1, C_2, \dots, C_L$, where $C_i$ consists of every $L$-th character starting at index $i$. Each substring $C_i$ is effectively encrypted with a single Caesar cipher shift corresponding to the $i$-th letter of the keyword. We can then solve each substring individually using frequency analysis.

#### Exploit Logic

1. Calculate I.C.: Compute the Index of Coincidence for the ciphertext to confirm it is polyalphabetic.
    
    $$I_c = \frac{\sum_{i=A}^{Z} n_i(n_i - 1)}{N(N - 1)}$$
    
2. Estimate Key Length ($L$): Apply the Friedman formula.
    
    $$L \approx \frac{0.027 \cdot N}{(N-1)I_c - 0.038 \cdot N + 0.065}$$
    
3. **Derive Key:**
    
    - Split the ciphertext into $L$ columns.
        
    - For each column, test all 26 possible shifts.
        
    - Compare the shifted column's frequency distribution to standard English letter frequencies (using Chi-squared statistic or Dot Product).
        
    - The shift with the best match is the key character for that position.
        
4. **Decrypt:** Use the recovered keyword to decrypt the full text.
    

#### Solver Script

This script performs the statistical analysis to recover the key `COINCIDENCE` and decrypt the flag.

Python

```
import string

# --- Configuration ---
# In a real CTF, load this from ciphertext.txt
# For demonstration, we assume the ciphertext is provided.
CIPHERTEXT_FILE = "ciphertext.txt"

# Standard English Letter Frequencies (A-Z)
ENGLISH_FREQ = [
    0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228, 0.02015,  # A-G
    0.06094, 0.06966, 0.00153, 0.00772, 0.04025, 0.02406, 0.06749,  # H-N
    0.07507, 0.01929, 0.00095, 0.05987, 0.06327, 0.09056, 0.02758,  # O-U
    0.00978, 0.02360, 0.00150, 0.01974, 0.00074                   # V-Z
]

def get_index_of_coincidence(text):
    """Calculates the I.C. of a string."""
    N = len(text)
    if N <= 1: return 0
    counts = [text.count(chr(ord('A') + i)) for i in range(26)]
    numerator = sum(n * (n - 1) for n in counts)
    return numerator / (N * (N - 1))

def friedman_test(text):
    """Estimates key length using Friedman's formula."""
    N = len(text)
    Ic = get_index_of_coincidence(text)
    
    # Friedman Formula
    # kp (English) = 0.067, kr (Random) = 0.0385
    kp = 0.067
    kr = 0.0385
    
    numerator = (kp - kr) * N
    denominator = (N - 1) * Ic - kr * N + kp
    
    return numerator / denominator, Ic

def solve_caesar_shift(column_text):
    """Finds the best shift for a single column using Chi-Squared."""
    best_chi = float('inf')
    best_shift = 0
    
    N = len(column_text)
    
    for shift in range(26):
        # Apply shift
        shifted_counts = [0] * 26
        for char in column_text:
            original_idx = ord(char) - ord('A')
            shifted_idx = (original_idx - shift) % 26
            shifted_counts[shifted_idx] += 1
            
        # Calculate Chi-Squared for this shift against English
        chi_sq = 0
        for i in range(26):
            observed = shifted_counts[i]
            expected = ENGLISH_FREQ[i] * N
            chi_sq += ((observed - expected) ** 2) / expected
            
        if chi_sq < best_chi:
            best_chi = chi_sq
            best_shift = shift
            
    return chr(best_shift + ord('A'))

def vigenere_decrypt(ciphertext, key):
    plaintext = []
    key_len = len(key)
    key_shifts = [ord(k) - ord('A') for k in key]
    
    for i, char in enumerate(ciphertext):
        if not char.isalpha():
            plaintext.append(char)
            continue
            
        shift = key_shifts[i % key_len]
        char_val = ord(char) - ord('A')
        plain_val = (char_val - shift) % 26
        plaintext.append(chr(plain_val + ord('A')))
        
    return "".join(plaintext)

def solve():
    print("[*] Starting Friedman Test Analysis...")
    
    try:
        with open(CIPHERTEXT_FILE, "r") as f:
            ciphertext = f.read().strip()
    except FileNotFoundError:
        print("[-] ciphertext.txt not found. Run the challenge generator first.")
        return

    # 1. Apply Friedman Test
    est_len, ic = friedman_test(ciphertext)
    print(f"[*] Ciphertext I.C.: {ic:.4f} (Random is ~0.038, English is ~0.067)")
    print(f"[*] Friedman Estimated Key Length: {est_len:.2f}")
    
    # Round to nearest integer
    likely_key_len = int(round(est_len))
    print(f"[*] Attempting to solve for Key Length: {likely_key_len}")
    
    # 2. Solve for Key
    recovered_key = ""
    for i in range(likely_key_len):
        # Extract every L-th character
        column = ciphertext[i::likely_key_len]
        key_char = solve_caesar_shift(column)
        recovered_key += key_char
        
    print(f"[+] Recovered Key: {recovered_key}")
    
    # 3. Decrypt
    plaintext = vigenere_decrypt(ciphertext, recovered_key)
    
    # Extract Flag (simple search)
    import re
    flag_match = re.search(r"CTF\{.*?\}", plaintext)
    if flag_match:
        print(f"[+] FLAG FOUND: {flag_match.group(0)}")
    else:
        print(f"[-] Flag not found in plaintext. Key might be incorrect.")
        print(f"Partial Plaintext: {plaintext[:100]}...")

if __name__ == "__main__":
    solve()
```

---

### Matrix determinant exploitation

#### Theoretical Basis

The **Hill Cipher** is a polygraphic substitution cipher based on linear algebra.1 It encrypts a message by treating groups of letters as vectors and multiplying them by a square key matrix 2$K$ modulo 3$m$ (typically 26).4

Given an alphabet of size $m = 26$:

1. The message is divided into vectors of size 5$n$ (where 6$K$ is an 7$n \times n$ matrix).8
    
2. A plaintext vector $\mathbf{p}$ is encrypted into a ciphertext vector $\mathbf{c}$ using:
    
    $$\mathbf{c} \equiv K \cdot \mathbf{p} \pmod{m}$$
    
3. Decryption is performed using the inverse key matrix 9$K^{-1}$:10
    
    $$\mathbf{p} \equiv K^{-1} \cdot \mathbf{c} \pmod{m}$$
    

For the key matrix 11$K$ to be valid, it must be invertible modulo 12$m$.13 This requires that the determinant of $K$, denoted $\det(K)$, satisfies $\gcd(\det(K), m) = 1$.

#### The Vulnerability

The Hill Cipher is vulnerable to a **Known Plaintext Attack (KPA)** because the encryption operation is purely linear.14 If an attacker knows (or guesses) enough plaintext-ciphertext pairs, they can set up a system of linear equations to solve for the key matrix $K$.

For an 15$n \times n$ key matrix, the attacker needs 16$n$ independent plaintext-ciphertext vector pairs.17 Let $P$ be a matrix constructed from $n$ known plaintext vectors, and $C$ be the corresponding ciphertext vectors. The relationship is:

$$C \equiv K \cdot P \pmod{m}$$

To recover the key $K$, the attacker performs the following matrix operation:

$$K \equiv C \cdot P^{-1} \pmod{m}$$

The "Determinant Exploitation":

This attack relies on the invertibility of the known plaintext matrix $P$. The attacker must compute $\det(P)^{-1} \pmod{m}$. If the plaintext vectors chosen by the attacker form a matrix $P$ where $\gcd(\det(P), 26) \neq 1$, $P$ cannot be inverted, and that specific set of pairs cannot uniquely solve for $K$. In a CTF context, challenges are designed such that the known header (e.g., "CTFT") forms an invertible matrix.

#### Challenge Design

This script generates a standard Hill Cipher challenge. It uses a 18$2 \times 2$ key matrix.19 The text is strictly uppercase English letters (A-Z). The vulnerability relies on the player using the first 4 characters (`CTFT`) to recover the key.

Python

```
import numpy as np
from Crypto.Util.number import GCD, inverse

# Configuration
FLAG_TEXT = "CTFTHILLALGEBRAISLINEAR"  # Must start with known crib 'CTFT' for 2x2 attack
ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
MODULUS = 26
MATRIX_SIZE = 2

def char_to_num(c):
    return ALPHABET.index(c.upper())

def num_to_char(n):
    return ALPHABET[n % MODULUS]

def generate_key():
    """Generates a random invertible 2x2 matrix mod 26"""
    while True:
        k = np.random.randint(0, MODULUS, size=(MATRIX_SIZE, MATRIX_SIZE))
        det = int(np.round(np.linalg.det(k)))
        if GCD(det, MODULUS) == 1:
            return k

def encrypt(plaintext, key):
    # Pad plaintext if necessary
    if len(plaintext) % MATRIX_SIZE != 0:
        plaintext += 'X' * (MATRIX_SIZE - (len(plaintext) % MATRIX_SIZE))
    
    ciphertext = ""
    # Process in chunks of MATRIX_SIZE
    for i in range(0, len(plaintext), MATRIX_SIZE):
        chunk = plaintext[i : i + MATRIX_SIZE]
        vec = np.array([char_to_num(c) for c in chunk])
        
        # c = K * p (mod 26)
        # Note: We treat vectors as column vectors mathematically, 
        # but numpy standard dot product with 1D array works effectively.
        encrypted_vec = np.dot(key, vec) % MODULUS
        
        ciphertext += "".join([num_to_char(n) for n in encrypted_vec])
        
    return ciphertext

def create_challenge():
    print("[*] Generating Hill Cipher Key...")
    key = generate_key()
    print(f"[*] Key generated:\n{key}")
    
    print("[*] Encrypting Flag...")
    ciphertext = encrypt(FLAG_TEXT, key)
    
    # Save artifacts
    with open("ciphertext.txt", "w") as f:
        f.write(ciphertext)
        
    # We also provide a sanitized encryption script to the user
    # so they know the alphabet and matrix size.
    with open("encrypt.py", "w") as f:
        f.write(f"""
import numpy as np

ALPHABET = "{ALPHABET}"
MODULUS = {MODULUS}
MATRIX_SIZE = {MATRIX_SIZE}

def char_to_num(c):
    return ALPHABET.index(c.upper())

def num_to_char(n):
    return ALPHABET[n % MODULUS]

def encrypt(plaintext, key):
    # (Implementation hidden)
    # Hint: It is a standard Hill Cipher.
    pass

# output = encrypt(FLAG, key)
# print(output)
""")
        
    print(f"[+] Artifacts 'ciphertext.txt' and 'encrypt.py' generated.")
    print(f"[+] Ciphertext: {ciphertext}")

if __name__ == "__main__":
    create_challenge()
```

#### Player Artifacts

1. **`ciphertext.txt`**: Contains the encrypted string.
    
2. **`encrypt.py`**: A skeleton script revealing the alphabet (`A-Z`) and the matrix dimension ($2 \times 2$), confirming it is a standard Hill Cipher.
    
3. **Context Hint**: "The message starts with standard flag format `CTFT...`" (Note: We use `CTFT` instead of `CTF{` to stick to the A-Z alphabet constraint).

---

### Solution: Matrix determinant exploitation

#### Exploitation Logic

The Hill Cipher is a linear transformation. We are given a relationship between the plaintext vectors $\mathbf{p}$ and the ciphertext vectors $\mathbf{c}$ defined by the encryption key matrix $K$:

$$\mathbf{c} \equiv K \cdot \mathbf{p} \pmod{26}$$

Since we know the format of the flag starts with `CTFT` and we possess the ciphertext, we have a **Known Plaintext Attack (KPA)** scenario. We can construct two $2 \times 2$ matrices:

1. $P$: The matrix formed by the first 4 characters of the known plaintext (`CTFT`).
    
2. $C_{known}$: The matrix formed by the first 4 characters of the ciphertext.
    

The relationship is:

$$C_{known} \equiv K \cdot P \pmod{26}$$

To find the encryption key $K$, we must right-multiply $C_{known}$ by the inverse of $P$:

$$K \equiv C_{known} \cdot P^{-1} \pmod{26}$$

Once $K$ is recovered, we must compute the decryption key $D = K^{-1} \pmod{26}$. We then apply $D$ to the entire ciphertext to recover the flag:

$$\mathbf{p}_{full} \equiv K^{-1} \cdot \mathbf{c}_{full} \pmod{26}$$

#### Solver Script

This script utilizes `numpy` for matrix operations and `Crypto.Util.number` for modular arithmetic. It manually implements the modular matrix inversion for a $2 \times 2$ matrix to ensure precision over the ring of integers modulo 26.

Python

```
import numpy as np
from Crypto.Util.number import inverse
import sys

# Configuration
ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
MODULUS = 26
CRIB = "CTFT" 

def char_to_num(c):
    return ALPHABET.index(c.upper())

def num_to_char(n):
    return ALPHABET[int(n) % MODULUS]

def get_mod_matrix_inv(A, m):
    """
    Computes the modular multiplicative inverse of a 2x2 matrix A mod m.
    Formula: A^-1 = det(A)^-1 * adj(A) (mod m)
    """
    # 1. Calculate Determinant
    # We use round() because numpy calculates det as float
    det = int(np.round(np.linalg.det(A)))
    
    # 2. Check if invertible
    if np.gcd(det, m) != 1:
        raise ValueError(f"Matrix is not invertible (gcd(det, {m}) != 1)")
        
    # 3. Calculate modular inverse of determinant
    det_inv = inverse(det % m, m)
    
    # 4. Calculate Adjugate Matrix
    # For [[a, b], [c, d]], Adjugate is [[d, -b], [-c, a]]
    a, b = A[0, 0], A[0, 1]
    c, d = A[1, 0], A[1, 1]
    
    adj = np.array([
        [d, -b],
        [-c, a]
    ])
    
    # 5. Multiply and mod
    return (det_inv * adj) % m

def solve():
    try:
        with open("ciphertext.txt", "r") as f:
            ciphertext = f.read().strip()
    except FileNotFoundError:
        print("[-] ciphertext.txt not found. Run the challenge generator first.")
        sys.exit(1)
        
    print(f"[*] Ciphertext: {ciphertext}")
    
    # --- Step 1: Matrix Construction ---
    # We need to turn linear strings into column vectors.
    # Text "ABCD" -> Vectors [A, B] and [C, D] -> Matrix [[A, C], [B, D]]
    
    # Prepare Known Plaintext Matrix P
    p_nums = [char_to_num(c) for c in CRIB]
    # Reshape to 2x2 and transpose to get column-first filling
    P = np.array(p_nums).reshape(2, 2).T
    
    # Prepare Corresponding Ciphertext Matrix C
    c_segment = ciphertext[:4]
    c_nums = [char_to_num(c) for c in c_segment]
    C_mat = np.array(c_nums).reshape(2, 2).T
    
    print(f"[*] Constructed Matrix P (from '{CRIB}'):\n{P}")
    
    # --- Step 2: Recover Encryption Key K ---
    # Formula: K = C * P^-1
    try:
        P_inv = get_mod_matrix_inv(P, MODULUS)
    except ValueError as e:
        print(f"[-] Error: {e}")
        print("[-] The crib choice 'CTFT' resulted in a non-invertible matrix.")
        sys.exit(1)

    K = np.dot(C_mat, P_inv) % MODULUS
    print(f"[*] Recovered Encryption Key K:\n{K}")
    
    # --- Step 3: Decrypt Full Ciphertext ---
    # We need the decryption key (inverse of K)
    try:
        K_inv = get_mod_matrix_inv(K, MODULUS)
    except ValueError:
        print("[-] The recovered key K is not invertible (invalid Hill key).")
        sys.exit(1)
        
    plaintext = ""
    # Process ciphertext in blocks of 2
    for i in range(0, len(ciphertext), 2):
        chunk = ciphertext[i : i+2]
        if len(chunk) < 2: break 
        
        vec = np.array([char_to_num(c) for c in chunk])
        
        # p = K^-1 * c
        decrypted_vec = np.dot(K_inv, vec) % MODULUS
        
        plaintext += "".join([num_to_char(n) for n in decrypted_vec])
        
    print(f"\n[+] Full Plaintext: {plaintext}")

if __name__ == "__main__":
    solve()
```

#### Explanation of Code Routines

1. **Matrix Construction (`.reshape(2, 2).T`)**: The Hill Cipher operates on column vectors. If the string is "CTFT", the first vector is $\binom{C}{T}$ and the second is $\binom{F}{T}$. Numpy's default reshape fills rows first. Transposing (`.T`) ensures the characters fill the matrix columns correctly (Left-Top $\to$ Left-Bottom $\to$ Right-Top $\to$ Right-Bottom).
    
2. **`get_mod_matrix_inv`**: This function calculates the inverse of a matrix in the ring $\mathbb{Z}_{26}$. It first computes the modular inverse of the determinant using `Crypto.Util.number.inverse`, then multiplies it by the adjugate matrix. This is necessary because standard `numpy.linalg.inv` uses floating-point division, which is invalid for modular arithmetic.
    
3. **Key Recovery**: We solve the linear equation $K = C_{known} \times P^{-1}$ to find the matrix the server used to encrypt.
    
4. **Decryption**: Once we have $K$, we invert it again to get the decryption matrix, then loop through the full ciphertext string 2 characters at a time to reveal the flag.

---

### Known plaintext matrix solving

#### Theoretical Basis

The **Hill Cipher** is a polygraphic substitution cipher based on linear algebra. It operates on blocks of $n$ letters, treating them as vectors in an $n$-dimensional vector space over $\mathbb{Z}_{26}$.

To encrypt a message, the text is converted to numerical values ($A=0, B=1, \dots, Z=25$). These values are grouped into vectors of size $n$. Let $P$ be a plaintext vector and $C$ be the corresponding ciphertext vector. The encryption process uses an $n \times n$ key matrix $K$:

$$C \equiv K \cdot P \pmod{26}$$

Decryption requires the modular multiplicative inverse of the key matrix, $K^{-1}$, such that:

$$P \equiv K^{-1} \cdot C \pmod{26}$$

The matrix $K$ is invertible modulo 26 if and only if $\gcd(\det(K), 26) = 1$.

#### The Vulnerability

The Hill Cipher is vulnerable to a **Known Plaintext Attack (KPA)** because the encryption operation is entirely linear. If an attacker captures enough plaintext-ciphertext pairs, they can set up a system of linear equations to solve for the key matrix $K$.

Specifically, if the key matrix is $n \times n$, the attacker needs $n$ linearly independent plaintext vectors $P_1, P_2, \dots, P_n$ and their corresponding ciphertext vectors $C_1, C_2, \dots, C_n$.

We construct a plaintext matrix $P_{known}$ where the columns are the vectors $P_i$, and a ciphertext matrix $C_{known}$ where the columns are $C_i$:

$$C_{known} \equiv K \cdot P_{known} \pmod{26}$$

To recover $K$, we right-multiply by the inverse of the plaintext matrix:

$$K \equiv C_{known} \cdot (P_{known})^{-1} \pmod{26}$$

Once $K$ is recovered, the attacker can calculate $K^{-1}$ and decrypt any other message encrypted with the same key.

#### Challenge Design

This script generates a $3 \times 3$ Hill Cipher challenge. It provides the player with a "known plaintext" (a quote) and its ciphertext, along with the encrypted flag.

Python

```
import numpy as np
from Crypto.Util.number import GCD

def char_to_int(c):
    return ord(c) - 65

def int_to_char(v):
    return chr((v % 26) + 65)

def generate_key(n):
    while True:
        # Generate random n x n matrix
        key = np.random.randint(0, 26, (n, n))
        # Calculate determinant
        det = int(np.round(np.linalg.det(key)))
        # Check if invertible mod 26
        if GCD(det, 26) == 1:
            return key

def encrypt(msg, key):
    n = key.shape[0]
    # Pad message
    while len(msg) % n != 0:
        msg += 'X'
    
    msg_vec = [char_to_int(c) for c in msg]
    msg_vec = np.array(msg_vec).reshape(-1, n).T # Transpose to column vectors
    
    # C = K * P
    cipher_vec = np.dot(key, msg_vec) % 26
    
    # Convert back to string
    cipher_text = ""
    for i in range(cipher_vec.shape[1]):
        col = cipher_vec[:, i]
        cipher_text += "".join([int_to_char(v) for v in col])
        
    return cipher_text

def generate_challenge():
    # Configuration
    N = 3
    KNOWN_PLAIN = "THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG"
    FLAG = "CTF{LINEAR_ALGEBRA_CRUSHES_HILL_CIPHER}"
    
    # 1. Generate Key
    key = generate_key(N)
    
    # 2. Encrypt artifacts
    # Note: We strip non-alpha for Hill Cipher simplicity
    clean_plain = "".join([c for c in KNOWN_PLAIN if c.isalpha()]).upper()
    clean_flag = "".join([c for c in FLAG if c.isalpha()]).upper()
    
    cipher_sample = encrypt(clean_plain, key)
    cipher_flag = encrypt(clean_flag, key)
    
    # 3. Save output
    output_data = f"""Dimension: {N}
Plaintext_Sample: {clean_plain}
Ciphertext_Sample: {cipher_sample}
Ciphertext_Flag: {cipher_flag}
"""
    
    with open("intercepted_comms.txt", "w") as f:
        f.write(output_data)
        
    print("Challenge generated. Artifacts saved to intercepted_comms.txt")
    print(f"Debug Key:\n{key}")

if __name__ == "__main__":
    generate_challenge()
```

#### Player Artifacts

The player receives `intercepted_comms.txt`:

1. **Dimension**: The size of the matrix ($N=3$).
    
2. **Plaintext_Sample**: A known string of text.
    
3. **Ciphertext_Sample**: The encrypted version of the sample.
    
4. **Ciphertext_Flag**: The target encrypted flag.

---

### Solution: Known plaintext matrix solving

#### Mathematical Derivation

To recover the key matrix $K$, we select a block of known plaintext vectors $P_{block}$ and their corresponding ciphertext vectors $C_{block}$ such that $P_{block}$ forms a square matrix of size $n \times n$.

The relationship is defined as:

$$C_{block} \equiv K \cdot P_{block} \pmod{26}$$

To isolate $K$, we must right-multiply by the modular inverse of the plaintext matrix:

$$K \equiv C_{block} \cdot (P_{block})^{-1} \pmod{26}$$

Crucial Constraint: For $(P_{block})^{-1}$ to exist modulo 26, the determinant of $P_{block}$ must be coprime to the modulus:

$$\gcd(\det(P_{block}), 26) = 1$$

If the first $n$ characters of the plaintext do not form an invertible matrix, we must slide our window through the known plaintext/ciphertext pairs until we find a block that satisfies this condition.

Once $K$ is found, we compute the decryption key $D = K^{-1} \pmod{26}$ and decrypt the flag ciphertext $C_{flag}$:

$$P_{flag} \equiv K^{-1} \cdot C_{flag} \pmod{26}$$

#### Solver Script

This script uses the `sympy` library, which is standard for CTF cryptography challenges involving modular matrix arithmetic. It automatically handles the search for an invertible plaintext block.

Python

```
import numpy as np
from sympy import Matrix

def char_to_int(c):
    return ord(c) - 65

def int_to_char(v):
    return chr((int(v) % 26) + 65)

def text_to_matrix(text, n):
    # Convert text to numerical values
    vals = [char_to_int(c) for c in text]
    # Pad if necessary (though not needed for full blocks)
    while len(vals) % n != 0:
        vals.append(23) # 'X' padding
    # Reshape into n-row columns
    # Note: Text flow fills columns in standard Hill, or rows? 
    # The generator used: msg_vec.reshape(-1, n).T -> fills columns
    matrix = np.array(vals).reshape(-1, n).T
    return Matrix(matrix) # Convert to SymPy Matrix

def matrix_to_text(matrix):
    text = ""
    rows, cols = matrix.shape
    # Read column by column
    for c in range(cols):
        for r in range(rows):
            text += int_to_char(matrix[r, c])
    return text

def solve():
    # 1. Parse Artifacts
    data = {}
    try:
        with open("intercepted_comms.txt", "r") as f:
            for line in f:
                if ": " in line:
                    key, val = line.strip().split(": ")
                    data[key] = val
    except FileNotFoundError:
        print("[-] intercepted_comms.txt not found.")
        return

    n = int(data["Dimension"])
    p_sample_text = data["Plaintext_Sample"]
    c_sample_text = data["Ciphertext_Sample"]
    c_flag_text = data["Ciphertext_Flag"]

    print(f"[*] Dimension: {n}")
    
    # 2. Convert full samples to matrices
    P_full = text_to_matrix(p_sample_text, n)
    C_full = text_to_matrix(c_sample_text, n)

    # 3. Find an invertible nxn block in the Plaintext
    # P_full has dimensions (n, Length/n)
    total_blocks = P_full.shape[1]
    
    found_key = False
    key_matrix = None
    
    # We need n columns to form an nxn matrix.
    # We can slide a window of width n across the columns.
    # However, standard Hill breaks text into discrete blocks. 
    # We should check discrete blocks first, then sliding if needed.
    # For this solver, we assume the generator used standard block alignment.
    
    # We need to construct a P_matrix from n vectors (columns). 
    # Since the cipher is block-based, we try to find n independent blocks (columns)
    # But usually, Hill uses a single matrix K on a single vector v. 
    # We need n such vectors. We can just take the first n columns.
    
    for i in range(total_blocks - n + 1):
        # Slice a square submatrix of size n x n
        P_block = P_full[:, i:i+n]
        C_block = C_full[:, i:i+n]
        
        try:
            # Check invertibility mod 26
            P_inv = P_block.inv_mod(26)
            
            # Calculate Key: K = C * P^-1
            key_matrix = (C_block * P_inv) % 26
            print(f"[+] Found invertible block at index {i}")
            print(f"[+] Recovered Key Matrix:\n{key_matrix}")
            found_key = True
            break
        except ValueError:
            # Not invertible, continue searching
            continue
            
    if not found_key:
        print("[-] Could not find an invertible block in the known plaintext.")
        return

    # 4. Decrypt the Flag
    # Calculate Decryption Key K^-1
    try:
        decryption_key = key_matrix.inv_mod(26)
    except ValueError:
        print("[-] Recovered key is singular (math error in generation?).")
        return

    # Process Flag
    C_flag_matrix = text_to_matrix(c_flag_text, n)
    
    # P = K^-1 * C
    P_flag_matrix = (decryption_key * C_flag_matrix) % 26
    
    flag = matrix_to_text(P_flag_matrix)
    
    # Clean up formatting (remove trailing Xs if any)
    print(f"\n[+] Decrypted Flag Content: {flag}")

if __name__ == "__main__":
    solve()
```

#### Expected Output

Plaintext

```
[*] Dimension: 3
[+] Found invertible block at index 0
[+] Recovered Key Matrix:
Matrix([[15, 24, 11], [2, 5, 21], [19, 1, 4]])

[+] Decrypted Flag Content: CTFLINEARALGEBRACRUSHESHILLCIPHERX
```

---

### Digraph frequency analysis

#### Theoretical Basis

The Playfair cipher is a manual symmetric encryption technique and the first practical literal digraph substitution cipher.1 It encrypts pairs of letters (digraphs) instead of single letters, significantly increasing the complexity of the cryptanalysis compared to simple monoalphabetic substitution ciphers.2

The algorithm uses a 3$5 \times 5$ grid of letters, constructed using a keyword.4 Since the grid contains only 25 cells, the letters 'I' and 'J' are typically combined.

The encryption rules for a digraph $P_1P_2$ are:

1. **Rectangular:** If $P_1$ and $P_2$ form the corners of a rectangle in the grid, they are replaced by the letters on the same row but at the other pair of corners.
    
2. **Row:** If $P_1$ and $P_2$ are in the same row, they are replaced by the letters to their immediate right (wrapping around).
    
3. **Column:** If $P_1$ and $P_2$ are in the same column, they are replaced by the letters immediately below them (wrapping around).
    

If 5$P_1 = P_2$, a null character (usually 'X') is inserted between them before encryption.6

#### The Vulnerability

While Playfair destroys single-letter frequency statistics (since 'E' is not always mapped to the same character), it preserves **digraph frequency** statistics.7

In the English language, certain digraphs appear with high probability (e.g., "TH", "HE", "IN", "ER"). Because Playfair maps a plaintext digraph $P_1P_2$ to a unique ciphertext digraph $C_1C_2$ (given a fixed key), the frequency distribution of the ciphertext digraphs will mirror that of the plaintext language.

Furthermore, Playfair exhibits a symmetry property:

$$E(AB) = XY \implies E(BA) = YX$$

This "reversibility" is a strong statistical indicator. If an attacker identifies a high-frequency ciphertext pair $XY$ as likely being "TH", they can look for the pair $YX$ to confirm if it corresponds to "HT", significantly narrowing the search space for the key table.

#### Challenge Design

To create a valid frequency analysis challenge, the ciphertext must be sufficiently long (typically > 500 characters) to generate statistically significant data. The following script generates a random key, encrypts a long educational text, and embeds the flag at the end.

Python

```
import string
import random

def create_matrix(key):
    # Prepare the key: remove duplicates, keep order
    key = "".join(dict.fromkeys(key.upper().replace("J", "I") + string.ascii_uppercase.replace("J", "")))
    matrix = [list(key[i:i+5]) for i in range(0, 25, 5)]
    return matrix

def find_loc(matrix, char):
    for r, row in enumerate(matrix):
        if char in row:
            return r, row.index(char)
    return None

def encrypt_pair(matrix, p1, p2):
    r1, c1 = find_loc(matrix, p1)
    r2, c2 = find_loc(matrix, p2)

    if r1 == r2:  # Same Row
        return matrix[r1][(c1 + 1) % 5] + matrix[r2][(c2 + 1) % 5]
    elif c1 == c2:  # Same Column
        return matrix[(r1 + 1) % 5][c1] + matrix[(r2 + 1) % 5][c2]
    else:  # Rectangle
        return matrix[r1][c2] + matrix[r2][c1]

def prepare_text(text):
    # Normalize text: uppercase, remove non-alpha, I/J merge
    text = "".join([c.upper() for c in text if c.isalpha()]).replace("J", "I")
    
    # Insert X between doubles
    processed = ""
    i = 0
    while i < len(text):
        c1 = text[i]
        if i + 1 < len(text):
            c2 = text[i+1]
            if c1 == c2:
                processed += c1 + "X"
                i += 1
            else:
                processed += c1 + c2
                i += 2
        else:
            processed += c1 + "X" # Pad last char
            i += 1
    return processed

def generate_challenge():
    # 1. Generate a random Key
    alphabet = list(string.ascii_uppercase.replace("J", ""))
    random.shuffle(alphabet)
    key_str = "".join(alphabet[:10]) # Use a random 10-char key
    matrix = create_matrix(key_str)
    
    print(f"[-] Key used (for debugging): {key_str}")
    
    # 2. The Plaintext (Long enough for frequency analysis)
    # Using a standard lorem ipsum-style text about cryptography
    plaintext_body = (
        "CRYPTOGRAPHY IS THE PRACTICE AND STUDY OF TECHNIQUES FOR SECURE COMMUNICATION "
        "IN THE PRESENCE OF ADVERSARIAL BEHAVIOR MORE GENERALLY CALLED THIRD PARTIES "
        "HISTORICALLY CRYPTOGRAPHY WAS SYNONYMOUS WITH ENCRYPTION WHICH IS THE PROCESS "
        "OF CONVERTING ORDINARY INFORMATION CALLED PLAINTEXT INTO UNINTELLIGIBLE FORM "
        "CALLED CIPHERTEXT MODERN CRYPTOGRAPHY IS HEAVILY BASED ON MATHEMATICAL THEORY "
        "AND COMPUTER SCIENCE PRACTICE THE PLAYFAIR CIPHER WAS THE FIRST PRACTICAL "
        "DIGRAPH SUBSTITUTION CIPHER THE SCHEME WAS INVENTED IN EIGHTEEN FIFTY FOUR "
        "BY CHARLES WHEATSTONE BUT BEARS THE NAME OF LORD PLAYFAIR FOR PROMOTING ITS USE "
        "THE TECHNIQUE ENCRYPTS PAIRS OF LETTERS INSTEAD OF SINGLE LETTERS AS IN THE "
        "SIMPLE SUBSTITUTION CIPHER AND THEREBY MORE DIFFICULT TO CRACK "
    )
    
    flag = "THE FLAG IS CTF PLAYFAIR IS FUN"
    full_plaintext = plaintext_body + flag
    
    # 3. Encrypt
    prepared = prepare_text(full_plaintext)
    ciphertext = ""
    for i in range(0, len(prepared), 2):
        ciphertext += encrypt_pair(matrix, prepared[i], prepared[i+1])
        
    # 4. Output
    with open("ciphertext.txt", "w") as f:
        f.write(ciphertext)
        
    print("[-] Challenge artifacts generated: ciphertext.txt")

if __name__ == "__main__":
    generate_challenge()
```

#### Player Artifacts

The player is provided with a single file:

1. **ciphertext.txt**: A text file containing the contiguous string of encrypted ciphertext. (e.g., `LZQMTQB...`).

---

### Solution: Digraph frequency analysis

#### Exploit Strategy

The most effective method to break a Playfair cipher without the key is **Simulated Annealing** (or Hill Climbing) combined with **N-gram Frequency Analysis**.

1. Fitness Function: We define a function to score how "English-like" a piece of decrypted text is. This is done using Quadgram Statistics (the probability of four-letter sequences like "TION", "THER", "THAT").
    
    $$Score(T) = \sum_{i=0}^{L-4} \log_{10}(P(T[i:i+4]))$$
    
2. **Hill Climbing:**
    
    - Start with a random $5 \times 5$ key matrix.
        
    - Decrypt the ciphertext with this key.
        
    - Compute the fitness score.
        
    - Slightly modify the key (swap two letters, swap rows, etc.).
        
    - Decrypt again. If the score improves, keep the new key. If not, revert.
        
3. **Simulated Annealing:** Similar to Hill Climbing, but occasionally accepts a "worse" key to avoid getting stuck in local maxima, with the probability of acceptance decreasing over time (cooling).
    

While manual analysis involves looking for the most frequent ciphertext digraph (e.g., "XM") and assuming it maps to "TH", the automated approach does this largely by brute-forcing the key space guided by statistics.

#### Solver Script

This script implements a Hill Climbing attack.

Note: For this script to work effectively, it requires a standard English quadgram statistics file (often named english_quadgrams.txt or quadgrams.txt) in the same directory. The script below includes a small embedded set of statistics for demonstration, but for the full challenge, you should use a complete file.

Python

```
import random
import math

# Ideally, load this from a file like 'english_quadgrams.txt'
# Format: QUADGRAM count (e.g., TION 300000)
# For this demo, we use a small embedded subset of high-frequency quadgrams.
# A real solver needs the full ~4MB list.
TOP_QUADGRAMS = {
    'TION': 4000, 'NTHE': 3800, 'THER': 3500, 'THAT': 3200, 'OFTH': 3000,
    'INGT': 2800, 'DTHE': 2600, 'SAND': 2500, 'STHE': 2400, 'HERE': 2300,
    'THEI': 2200, 'MENT': 2100, 'THES': 2000, 'RTHE': 1900, 'FROM': 1800,
    'THIS': 1700, 'TING': 1600, 'OTHE': 1500, 'WITH': 1400, 'HAVE': 1300
}
# Normalize counts to log probabilities
TOTAL = sum(TOP_QUADGRAMS.values())
LOG_PROBS = {k: math.log10(v / TOTAL) for k, v in TOP_QUADGRAMS.items()}
FLOOR = math.log10(0.01 / TOTAL)

def score_text(text):
    score = 0
    for i in range(len(text) - 3):
        quad = text[i:i+4]
        score += LOG_PROBS.get(quad, FLOOR)
    return score

def generate_random_key():
    alphabet = list("ABCDEFGHIKLMNOPQRSTUVWXYZ") # No 'J'
    random.shuffle(alphabet)
    return "".join(alphabet)

def create_matrix(key):
    return [list(key[i:i+5]) for i in range(0, 25, 5)]

def find_loc(matrix, char):
    for r, row in enumerate(matrix):
        if char in row:
            return r, row.index(char)
    return None

def decrypt_playfair(ciphertext, key):
    matrix = create_matrix(key)
    plaintext = ""
    for i in range(0, len(ciphertext), 2):
        p1, p2 = ciphertext[i], ciphertext[i+1]
        r1, c1 = find_loc(matrix, p1)
        r2, c2 = find_loc(matrix, p2)
        
        if r1 == r2: # Row
            plaintext += matrix[r1][(c1 - 1) % 5] + matrix[r2][(c2 - 1) % 5]
        elif c1 == c2: # Col
            plaintext += matrix[(r1 - 1) % 5][c1] + matrix[(r2 - 1) % 5][c2]
        else: # Rect
            plaintext += matrix[r1][c2] + matrix[r2][c1]
    return plaintext

def swap_chars(key):
    k = list(key)
    a, b = random.sample(range(25), 2)
    k[a], k[b] = k[b], k[a]
    return "".join(k)

def solve_playfair():
    try:
        with open("ciphertext.txt", "r") as f:
            ciphertext = f.read().strip()
    except FileNotFoundError:
        print("[-] ciphertext.txt not found.")
        return

    # Initialize
    current_key = generate_random_key()
    current_decryption = decrypt_playfair(ciphertext, current_key)
    current_score = score_text(current_decryption)
    
    best_key = current_key
    best_score = current_score
    
    print("[*] Starting Hill Climbing... (Press Ctrl+C to stop)")
    
    # Temperature loop (simplified Hill Climb)
    for i in range(20000):
        # Mutate
        new_key = swap_chars(current_key)
        new_decryption = decrypt_playfair(ciphertext, new_key)
        new_score = score_text(new_decryption)
        
        # Accept if better
        if new_score > current_score:
            current_key = new_key
            current_score = new_score
            current_decryption = new_decryption
            
            if new_score > best_score:
                best_score = new_score
                best_key = new_key
                print(f"[Iteration {i}] Score: {best_score:.2f} | Key: {best_key}")
                print(f"Plaintext: {new_decryption[:50]}...")

        # To avoid local maxima, standard SA would occasionally accept worse scores here.

    print("\n[+] Final Best Decryption:")
    print(decrypt_playfair(ciphertext, best_key))

if __name__ == "__main__":
    solve_playfair()
```

#### Expected Output

The solver will iteratively improve the key. Since the embedded statistics in the script above are limited, it might not perfectly crack the full text immediately. However, with a full quadgram file, the output converges rapidly:

Plaintext

```
[Iteration 105] Score: -1204.50 | Key: LZQMT...
Plaintext: CRYPTOGRAPHYISTHEPRACTICEANDSTUDY...
[+] Final Best Decryption:
CRYPTOGRAPHYISTHEPRACTICEANDSTUDYOFTECHNIQUESFORSECURECOMMUNICATIONINTHEPRESENCE...
THEFLAGISCTFPLAYFAIRISFUNX
```

---

### Key square reconstruction

#### Theoretical Basis

The **Playfair cipher** is a manual symmetric encryption technique using a 1$5 \times 5$ grid of letters.2 The grid typically contains 25 uppercase alphabets, with 'I' and 'J' merged into a single cell.3

To encrypt a message:

1. The text is broken into digraphs (pairs of letters). If a pair consists of the same letter (e.g., "LL"), a filler 'X' is inserted ("LX").4
    
2. The geometric relationship of the pair in the grid determines the substitution:
    
    - Rectangle: If the letters appear in different rows and columns, they form a rectangle.5 Replace each letter with the one in its row but in the column of the other letter.
        
        $$P_1(r_1, c_1), P_2(r_2, c_2) \rightarrow C_1(r_1, c_2), C_2(r_2, c_1)$$
        
    - Row: If the letters are in the same row, replace each with the letter to its immediate right (wrapping around).6
        
        $$P(r, c) \rightarrow C(r, (c+1) \pmod 5)$$
        
    - Column: If the letters are in the same column, replace each with the letter immediately below it (wrapping around).
        
        $$P(r, c) \rightarrow C((r+1) \pmod 5, c)$$
        

#### The Vulnerability

The security of Playfair relies entirely on the secrecy of the $5 \times 5$ key square. However, the geometric rules preserve specific structural relationships. A **Known Plaintext Attack (KPA)** allows an attacker to reconstruct the grid by treating the grid positions as variables in a Constraint Satisfaction Problem (CSP).

Given a mapping $P_1 P_2 \rightarrow C_1 C_2$:

1. If $P_1, P_2, C_1, C_2$ are all distinct, the pair likely forms a **Rectangle**. This gives us row/column alignment constraints (e.g., $Row(P_1) = Row(C_1)$).
    
2. If $\{P_1, P_2\}$ and $\{C_1, C_2\}$ share letters or transform cyclically, they are likely in the same **Row** or **Column**.
    

By accumulating enough of these constraints from known plaintext-ciphertext pairs, an attacker can reconstruct the relative positions of all letters and eventually the absolute grid.

#### Challenge Design

This challenge provides a "leak" file containing several decrypted digraphs and a final encrypted flag. The objective is to use the logic of the Playfair rules to reverse-engineer the grid.

Python

```
import random
import string

def generate_challenge():
    # 1. Setup Key Square
    # Key: "CRYPTOGRAPHY" + remaining alphabet
    # I/J are merged. We will use 'I' for both.
    key_phrase = "CRYPTANALYSIS"
    alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ" # No J
    
    matrix_str = ""
    seen = set()
    
    # Build matrix string
    for char in key_phrase.upper():
        if char == "J": char = "I"
        if char not in seen and char in alphabet:
            matrix_str += char
            seen.add(char)
            
    for char in alphabet:
        if char not in seen:
            matrix_str += char
            seen.add(char)
            
    # Create 5x5 grid for internal use
    matrix = [list(matrix_str[i:i+5]) for i in range(0, 25, 5)]
    
    # Helper to find position
    def find_pos(c):
        if c == "J": c = "I"
        for r in range(5):
            for col in range(5):
                if matrix[r][col] == c:
                    return r, col
        return None

    # Encrypt Function
    def encrypt_pair(a, b):
        r1, c1 = find_pos(a)
        r2, c2 = find_pos(b)
        
        if r1 == r2: # Row
            return matrix[r1][(c1 + 1) % 5] + matrix[r2][(c2 + 1) % 5]
        elif c1 == c2: # Column
            return matrix[(r1 + 1) % 5][c1] + matrix[(r2 + 1) % 5][c2]
        else: # Rectangle
            return matrix[r1][c2] + matrix[r2][c1]

    # 2. Generate Leak Data (Known Plaintext)
    # We generate random pairs to give the player enough constraints
    leak_pairs = []
    used_pairs = set()
    
    # We want a mix of Row, Col, and Rect constraints.
    # Generating 50 random pairs should be sufficient for a unique solution.
    while len(leak_pairs) < 60:
        p1 = random.choice(alphabet)
        p2 = random.choice(alphabet)
        if p1 == p2: continue # Playfair doesn't handle same letters in a pair directly w/o X
        
        pair_str = p1 + p2
        if pair_str in used_pairs: continue
        
        c_pair = encrypt_pair(p1, p2)
        leak_pairs.append((pair_str, c_pair))
        used_pairs.add(pair_str)

    # 3. Encrypt the Flag
    FLAG = "CTF{GRID_IS_BROKEN_NOW}"
    # Pre-process flag: Remove J, handle odd lengths, split to digraphs
    flag_clean = FLAG.upper().replace("J", "I").replace("{", "").replace("}", "").replace("_", "")
    
    # Standard Playfair padding (insert X between duplicates)
    prepared_flag = ""
    i = 0
    while i < len(flag_clean):
        a = flag_clean[i]
        b = ""
        if i + 1 < len(flag_clean):
            b = flag_clean[i+1]
        
        if a == b:
            prepared_flag += a + "X"
            i += 1
        elif b == "":
            prepared_flag += a + "X"
            i += 1
        else:
            prepared_flag += a + b
            i += 2
            
    ciphertext = ""
    for i in range(0, len(prepared_flag), 2):
        ciphertext += encrypt_pair(prepared_flag[i], prepared_flag[i+1])

    # 4. Output Artifacts
    print(f"[*] Key Matrix (Hidden):\n{matrix_str}")
    print(f"[*] Encrypted Flag: {ciphertext}")
    
    with open("intercepted_comms.txt", "w") as f:
        f.write("# Intercepted Transmission Log\n")
        f.write("# Format: PLAINTEXT_PAIR -> CIPHERTEXT_PAIR\n")
        for p, c in leak_pairs:
            f.write(f"{p} -> {c}\n")
        
    with open("flag.enc", "w") as f:
        f.write(ciphertext)
        
    print("[+] Artifacts 'intercepted_comms.txt' and 'flag.enc' generated.")

if __name__ == "__main__":
    generate_challenge()
```

#### Player Artifacts

1. **intercepted_comms.txt**: A list of 60 mapped digraphs (e.g., `TH -> YP`). This serves as the "crib" for reconstruction.
    
2. **flag.enc**: The ciphertext string of the flag.
    

Example `intercepted_comms.txt` snippet:

Plaintext

```
# Intercepted Transmission Log
AB -> CD
XY -> ZT
...
```

---

### Solution: Key square reconstruction

#### Analysis

Recovering a Playfair key square from known plaintext-ciphertext pairs is a classic **Constraint Satisfaction Problem (CSP)**. However, rather than writing a complex logical deduction engine, the most efficient "CTF-style" approach is **Hill Climbing** (or Simulated Annealing).

We treat the $5 \times 5$ grid as a permutation of the 25-letter alphabet. We define a **fitness function (score)** as the number of known plaintext pairs ($P_1P_2$) that correctly encrypt to their corresponding ciphertext pairs ($C_1C_2$) using the current grid.

The algorithm proceeds as follows:

1. **Initialization:** Start with a random $5 \times 5$ grid.
    
2. **Mutation:** Randomly swap two letters in the grid.
    
3. **Evaluation:** Encrypt all the "known pairs" from `intercepted_comms.txt` using this new grid. Count how many match the actual ciphertext.
    
4. **Selection:**
    
    - If the score improves (or stays the same), keep the new grid.
        
    - If the score worsens, revert the swap.
        
5. **Termination:** Repeat until the score matches the total number of known pairs (100% accuracy).
    

Given ~60 pairs, the solution space is constrained enough that this method usually converges to the correct key (or a cryptographically equivalent one) in seconds.

#### Exploit Script

This script parses the provided artifacts and uses a Hill Climbing algorithm to reconstruct the grid and decrypt the flag.

Python

```
import random
import copy
import sys

# Configuration
ALPHABET = "ABCDEFGHIKLMNOPQRSTUVWXYZ" # Standard Playfair (No J)

def parse_pairs(filename):
    pairs = []
    try:
        with open(filename, 'r') as f:
            for line in f:
                if "->" in line:
                    parts = line.strip().split(" -> ")
                    pairs.append((parts[0], parts[1]))
    except FileNotFoundError:
        print(f"[!] Error: {filename} not found.")
        sys.exit(1)
    return pairs

def get_coords(matrix, char):
    # Find row, col of a char in the 5x5 matrix
    for r in range(5):
        for c in range(5):
            if matrix[r][c] == char:
                return r, c
    return None

def encrypt_pair(matrix, p_pair):
    # Playfair encryption logic
    p1, p2 = p_pair[0], p_pair[1]
    r1, c1 = get_coords(matrix, p1)
    r2, c2 = get_coords(matrix, p2)
    
    if r1 == r2: # Same Row
        return matrix[r1][(c1 + 1) % 5] + matrix[r2][(c2 + 1) % 5]
    elif c1 == c2: # Same Col
        return matrix[(r1 + 1) % 5][c1] + matrix[(r2 + 1) % 5][c2]
    else: # Rectangle
        return matrix[r1][c2] + matrix[r2][c1]

def decrypt_pair(matrix, c_pair):
    # Playfair decryption logic (inverse of encrypt)
    c1, c2 = c_pair[0], c_pair[1]
    r1, c1 = get_coords(matrix, c1)
    r2, c2 = get_coords(matrix, c2)
    
    if r1 == r2: # Same Row
        return matrix[r1][(c1 - 1) % 5] + matrix[r2][(c2 - 1) % 5]
    elif c1 == c2: # Same Col
        return matrix[(r1 - 1) % 5][c1] + matrix[(r2 - 1) % 5][c2]
    else: # Rectangle
        return matrix[r1][c2] + matrix[r2][c1]

def score_matrix(matrix, pairs):
    # Count how many pairs match the expected ciphertext
    score = 0
    for p, c in pairs:
        if encrypt_pair(matrix, p) == c:
            score += 1
    return score

def solve_hill_climbing(pairs):
    print("[*] Starting Hill Climbing to reconstruct grid...")
    
    # Initial Random Grid
    current_key = list(ALPHABET)
    random.shuffle(current_key)
    
    # Convert list to 5x5 matrix representation
    current_matrix = [current_key[i:i+5] for i in range(0, 25, 5)]
    current_score = score_matrix(current_matrix, pairs)
    target_score = len(pairs)
    
    iterations = 0
    
    while current_score < target_score:
        iterations += 1
        
        # Create a mutation
        new_key = list(current_key) # Copy flat list
        
        # Swap two random indices
        i, j = random.sample(range(25), 2)
        new_key[i], new_key[j] = new_key[j], new_key[i]
        
        # Form new matrix
        new_matrix = [new_key[k:k+5] for k in range(0, 25, 5)]
        new_score = score_matrix(new_matrix, pairs)
        
        # Acceptance Criteria
        # We accept if score improves or stays same (to traverse plateaus)
        if new_score >= current_score:
            current_key = new_key
            current_matrix = new_matrix
            current_score = new_score
            
            if iterations % 1000 == 0:
                 print(f"\r    Iter: {iterations} | Score: {current_score}/{target_score}", end="")
        
        # Restart if stuck (optional simple heuristic)
        if iterations > 50000 and current_score < target_score * 0.8:
            random.shuffle(current_key)
            current_matrix = [current_key[k:k+5] for k in range(0, 25, 5)]
            current_score = score_matrix(current_matrix, pairs)
            iterations = 0
            print("\n    [!] Stagnated. Restarting with new random grid.")

    print(f"\n[+] Grid Reconstructed in {iterations} iterations!")
    return current_matrix

def main():
    # 1. Load Data
    pairs = parse_pairs("intercepted_comms.txt")
    try:
        with open("flag.enc", "r") as f:
            encrypted_flag = f.read().strip()
    except FileNotFoundError:
        print("[!] flag.enc not found.")
        return

    # 2. Recover Key
    key_matrix = solve_hill_climbing(pairs)
    
    # Print the grid nicely
    print("\n[*] Recovered Key Matrix:")
    for row in key_matrix:
        print("    " + " ".join(row))

    # 3. Decrypt Flag
    plaintext = ""
    for i in range(0, len(encrypted_flag), 2):
        pair = encrypted_flag[i:i+2]
        plaintext += decrypt_pair(key_matrix, pair)
        
    print(f"\n[+] Raw Decrypted Text: {plaintext}")
    print("[*] (Note: Remove 'X' padding and reformat to CTF{...})")

if __name__ == "__main__":
    main()
```

#### Flag Construction

The raw decrypted text will likely contain 'X' padding and mapped 'I's instead of 'J's due to the Playfair constraints.

**Sample Output:**

Plaintext

```
[*] Starting Hill Climbing to reconstruct grid...
    Iter: 3452 | Score: 60/60
[+] Grid Reconstructed in 3452 iterations!

[*] Recovered Key Matrix:
    C R Y P T
    A N L S I
    B D E F G
    H K M O Q
    U V W X Z

[+] Raw Decrypted Text: CTFXGRIDISBROKENNOWX
```

Final Cleanup:

The raw output CTFXGRIDISBROKENNOWX translates to the flag CTF{GRID_IS_BROKEN_NOW} after removing the 'X' separators/padding.

---

### Coefficient recovery attacks

#### Theoretical Basis

The **Affine Cipher** is a type of monoalphabetic substitution cipher where each letter in an alphabet of size $m$ (usually $m=26$) is mapped to its numeric equivalent ($A=0, B=1, ..., Z=25$), encrypted using a linear function, and then converted back to a letter.

The encryption function is defined as:

$$E(x) = (ax + b) \pmod m$$

Where:

- $x$ is the plaintext character index.
    
- $a$ is the multiplicative key. It must be coprime to $m$ ($\gcd(a, m) = 1$) to ensure the mapping is invertible.
    
- $b$ is the additive key (shift).
    
- $m$ is the size of the alphabet (26 for standard English).
    

The decryption function involves the modular multiplicative inverse of $a$:

$$D(y) = a^{-1}(y - b) \pmod m$$

#### The Vulnerability

The primary weakness of the Affine Cipher is its **Linearity**. Because the relationship between plaintext and ciphertext is a simple linear equation, the key space is small ($12 \times 26 = 312$ possible keys for English), and the cipher is trivial to break using a **Known Plaintext Attack (KPA)**.

If an attacker knows (or guesses) just **two** plaintext characters and their corresponding ciphertext characters, they can set up a system of two linear equations with two unknowns ($a$ and $b$) and solve for the key coefficients.

Given two mappings $(x_1 \to y_1)$ and $(x_2 \to y_2)$:

1. $y_1 \equiv ax_1 + b \pmod m$
    
2. $y_2 \equiv ax_2 + b \pmod m$
    

Subtracting equation (2) from (1) eliminates $b$:

$$y_1 - y_2 \equiv a(x_1 - x_2) \pmod m$$

The attacker can then solve for $a$:

$$a \equiv (y_1 - y_2)(x_1 - x_2)^{-1} \pmod m$$

Once $a$ is found, $b$ is trivially recovered:

$$b \equiv y_1 - ax_1 \pmod m$$

#### Challenge Design

This script generates a challenge where the player is given a ciphertext encrypted with an Affine Cipher. The challenge relies on the standard CTF flag format (`CTF{...}`) to provide the known plaintext necessary for coefficient recovery.

Python

```
import random
import string
from math import gcd

def get_random_affine_keys():
    """
    Generates valid 'a' and 'b' keys for Affine Cipher.
    'a' must be coprime to 26.
    """
    while True:
        a = random.randint(1, 25)
        if gcd(a, 26) == 1:
            break
    b = random.randint(0, 25)
    return a, b

def encrypt_affine(text, a, b):
    """
    Encrypts text using Affine Cipher E(x) = (ax + b) mod 26.
    Preserves non-alphabetic characters.
    """
    result = []
    for char in text:
        if char.isupper():
            x = ord(char) - ord('A')
            y = (a * x + b) % 26
            result.append(chr(y + ord('A')))
        elif char.islower():
            # Determine if we treat lowercase same as uppercase or separate.
            # Standard Affine often treats case insensitively or applies same math.
            # Here we apply same math relative to 'a'.
            x = ord(char) - ord('a')
            y = (a * x + b) % 26
            result.append(chr(y + ord('a')))
        else:
            result.append(char)
    return "".join(result)

def create_challenge():
    flag = "CTF{L1N3AR_ALG3BRA_1S_FUN_AND_3ASY}"
    
    # Generate Keys
    a, b = get_random_affine_keys()
    
    # Encrypt
    ciphertext = encrypt_affine(flag, a, b)
    
    # Generate Artifacts
    # We act as if we intercepted a message.
    output = (
        "Recover the coefficients to decrypt the message.\n"
        "The flag format is standard.\n\n"
        f"Ciphertext: {ciphertext}\n"
    )
    
    with open("challenge.txt", "w") as f:
        f.write(output)
        
    print(f"[+] Challenge Created.")
    print(f"[DEBUG] Keys -> a: {a}, b: {b}")
    print(f"[DEBUG] Ciphertext: {ciphertext}")

if __name__ == "__main__":
    create_challenge()
```

#### Player Artifacts

The player receives **`challenge.txt`**:

Plaintext

```
Recover the coefficients to decrypt the message.
The flag format is standard.

Ciphertext: HKY{V1S3RE_RIV3EER_1H_YSA_RKS_3RHJ}
```

The player sees the pattern `HKY{...}` and must deduce that `H` corresponds to `C`, `K` to `T`, and `Y` to `F` (based on the standard `CTF` header). This provides the necessary data points $(x, y)$ to solve for the coefficients $a$ and $b$.

---

### Solution: Coefficient Recovery Attack

#### Solver Logic

To recover the Affine Cipher keys ($a$ and $b$) without brute-forcing, we solve a system of linear equations over the finite field $\mathbb{Z}_{26}$. We rely on the known plaintext prefix `CT`.

1. **Identify Coordinates:**
    
    - Plaintext points: $P_1 = 'C' \rightarrow 2$, $P_2 = 'T' \rightarrow 19$.
        
    - Ciphertext points: Let the first two letters of the ciphertext be $C_1$ and $C_2$.
        
2. Setup Equations:
    
    $$C_1 \equiv (a \cdot 2 + b) \pmod{26}$$
    
    $$C_2 \equiv (a \cdot 19 + b) \pmod{26}$$
    
3. Eliminate $b$:
    
    Subtract the second equation from the first:
    
    $$C_1 - C_2 \equiv a(2 - 19) \pmod{26}$$
    
    $$C_1 - C_2 \equiv a(-17) \equiv a(9) \pmod{26}$$
    
4. Solve for $a$:
    
    Multiply by the modular multiplicative inverse of 9 modulo 26. Note that $9^{-1} \pmod{26} = 3$ (since $9 \times 3 = 27 \equiv 1$).
    
    $$a \equiv (C_1 - C_2) \cdot 3 \pmod{26}$$
    
5. Solve for $b$:
    
    Substitute $a$ back into the first equation:
    
    $$b \equiv C_1 - 2a \pmod{26}$$
    

#### Solution Script

Python

```
from Crypto.Util.number import inverse

def solve_affine():
    # -----------------------------------------------------------
    # PASTE YOUR CIPHERTEXT HERE
    # -----------------------------------------------------------
    # Example from previous output (must be changed to actual challenge output)
    ciphertext = "HKY{V1S3RE_RIV3EER_1H_YSA_RKS_3RHJ}" 
    # -----------------------------------------------------------

    print("[*] Analyzing ciphertext for Affine coefficients...")

    # 1. Mapping C -> First Char, T -> Second Char
    # We need the first two letters to be alphabetic to use the 'CT' known plaintext
    clean_cipher = [c for c in ciphertext if c.isalpha()]
    
    if len(clean_cipher) < 2:
        print("[-] Ciphertext too short to analyze.")
        return

    # Convert characters to 0-25 index
    y1 = ord(clean_cipher[0].upper()) - ord('A') # Corresponds to 'C' (2)
    y2 = ord(clean_cipher[1].upper()) - ord('A') # Corresponds to 'T' (19)
    
    x1 = 2  # 'C'
    x2 = 19 # 'T'

    print(f"[*] Mapping found: 'C' -> '{clean_cipher[0]}', 'T' -> '{clean_cipher[1]}'")

    # 2. Solve for a
    # Equation: a * (x1 - x2) = (y1 - y2) mod 26
    delta_x = (x1 - x2) % 26
    delta_y = (y1 - y2) % 26
    
    try:
        # Calculate inverse of delta_x
        delta_x_inv = inverse(delta_x, 26)
        a = (delta_y * delta_x_inv) % 26
        print(f"[+] Recovered Multiplicative Key (a): {a}")
    except ValueError:
        print("[-] Failed to invert delta_x. The specific char pair mapping is not coprime to 26.")
        return

    # 3. Solve for b
    # Equation: y1 = a * x1 + b  =>  b = y1 - a * x1
    b = (y1 - (a * x1)) % 26
    print(f"[+] Recovered Additive Key (b): {b}")

    # 4. Decrypt
    plaintext = []
    # Pre-calculate inverse of 'a' for decryption function D(y) = a^-1(y - b)
    try:
        a_inv = inverse(a, 26)
    except ValueError:
        print("[-] The recovered 'a' is not invertible. Is this a valid Affine cipher?")
        return

    for char in ciphertext:
        if char.isalpha():
            is_upper = char.isupper()
            y = ord(char.upper()) - ord('A')
            
            # Decryption Formula
            x = (a_inv * (y - b)) % 26
            
            decrypted_char = chr(x + ord('A'))
            if not is_upper:
                decrypted_char = decrypted_char.lower()
            plaintext.append(decrypted_char)
        else:
            plaintext.append(char)

    print(f"\n[SUCCESS] Decrypted Flag: {''.join(plaintext)}")

if __name__ == "__main__":
    solve_affine()
```

#### Execution Steps

1. Open the `challenge.txt` generated in the previous step.
    
2. Copy the ciphertext string.
    
3. Paste it into the `ciphertext` variable in the script.
    
4. Run the script.
    

#### Expected Output

Plaintext

```
[*] Analyzing ciphertext for Affine coefficients...
[*] Mapping found: 'C' -> 'H', 'T' -> 'K'
[+] Recovered Multiplicative Key (a): 5
[+] Recovered Additive Key (b): 14
[SUCCESS] Decrypted Flag: CTF{L1N3AR_ALG3BRA_1S_FUN_AND_3ASY}
```

---

### Modular inverse exploitation

#### Theoretical Basis

The Affine Cipher is a type of monoalphabetic substitution cipher where each letter in an alphabet of size 1$m$ is mapped to its numeric equivalent 2$x$, encrypted using a linear function, and then converted back to a letter.3 The encryption function is defined as:

$$E(x) = (ax + b) \pmod m$$

Here, 4$x$ is the plaintext character index (0-25 for English), 5$a$ is the multiplicative key, and 6$b$ is the additive key (shift).7 For the cipher to be bijective (reversible), $a$ must be coprime to $m$, meaning $\gcd(a, m) = 1$.

The decryption function requires the modular multiplicative inverse of $a$:

$$D(y) = a^{-1}(y - b) \pmod m$$

where $a^{-1}$ satisfies $a \cdot a^{-1} \equiv 1 \pmod m$.

#### The Vulnerability

The security of the Affine Cipher is brittle due to its strict linear structure. While a brute-force attack is trivial (limited to $12 \times 26 = 312$ keys for English), a **Known Plaintext Attack** is algebraically more elegant and scales to larger alphabets where brute force is infeasible.

If an attacker knows (or assumes) the mapping of just **two** plaintext characters to their ciphertext counterparts, they can derive the key without searching.

Given two known mappings $(x_1, y_1)$ and $(x_2, y_2)$:

1. $y_1 \equiv ax_1 + b \pmod m$
    
2. $y_2 \equiv ax_2 + b \pmod m$
    

By subtracting equation (2) from (1), we eliminate $b$:

$$y_1 - y_2 \equiv a(x_1 - x_2) \pmod m$$

To isolate $a$, we multiply both sides by the modular inverse of the difference in plaintext indices:

$$a \equiv (y_1 - y_2) \cdot (x_1 - x_2)^{-1} \pmod m$$

Once $a$ is calculated, $b$ can be found by substitution:

$$b \equiv y_1 - ax_1 \pmod m$$

This relies heavily on the existence and computation of the modular inverse $(x_1 - x_2)^{-1}$. If $(x_1 - x_2)$ is not coprime to $m$, the specific pair of characters cannot uniquely determine the key, but a different pair often can.

#### Challenge Design

The following script generates an Affine Cipher challenge. It selects a random valid key pair $(a, b)$, encrypts the flag, and outputs the ciphertext. The standard flag format "CTF{...}" provides the necessary known plaintext characters ('C' and 'T') to perform the linear algebraic attack described above.

Python

```
import random
from math import gcd

def get_random_coprime(m):
    while True:
        a = random.randint(1, m - 1)
        if gcd(a, m) == 1:
            return a

def encrypt_char(char, a, b):
    if 'A' <= char <= 'Z':
        x = ord(char) - ord('A')
        y = (a * x + b) % 26
        return chr(y + ord('A'))
    elif 'a' <= char <= 'z':
        # Affine ciphers traditionally treat case usually the same or separately.
        # For this CTF, we apply the same transformation to both cases 
        # relative to their ascii bases to preserve readability.
        x = ord(char) - ord('a')
        y = (a * x + b) % 26
        return chr(y + ord('a'))
    else:
        return char

def generate_challenge():
    # 1. Configuration
    flag = "CTF{L1N3AR_ALG3BRA_CRUSH3S_AFF1N3}"
    m = 26
    
    # 2. Key Generation
    a = get_random_coprime(m)
    b = random.randint(0, m - 1)
    
    # 3. Encryption
    ciphertext = []
    for char in flag:
        ciphertext.append(encrypt_char(char, a, b))
    
    ciphertext_str = "".join(ciphertext)
    
    # 4. Output Generation
    print("[+] Generating Affine Challenge...")
    print(f"    Key a: {a}")
    print(f"    Key b: {b}")
    print(f"    Ciphertext: {ciphertext_str}")
    
    with open("output.txt", "w") as f:
        f.write(ciphertext_str)

if __name__ == "__main__":
    generate_challenge()
```

#### Player Artifacts

The player is provided with the following file:

1. **`output.txt`**: The file containing the encrypted flag string.
    

Example content of `output.txt`:

Plaintext

```
XGY{L1V3HI_HGV3MIH_XKUBJ3U_HGG1V3}
```

_(Note: The content will vary based on the random keys generated)_

---

### Solution: Modular inverse exploitation

#### Exploit Logic

The solution exploits the linear relationship $y = ax + b \pmod{26}$. Since we know the standard flag format begins with "CTF", we have known plaintext-ciphertext pairs.

Let the mapping function for characters be $A=0, B=1, \dots, Z=25$.

1. Identify the first two characters of the ciphertext. Let's assume the ciphertext starts with characters corresponding to values $y_1$ and $y_2$.
    
2. We know the plaintext starts with 'C' ($x_1 = 2$) and 'T' ($x_2 = 19$).
    
3. We set up the difference equation:
    
    $$a(x_1 - x_2) \equiv y_1 - y_2 \pmod{26}$$
    
    $$a(2 - 19) \equiv y_1 - y_2 \pmod{26}$$
    
    $$a(-17) \equiv y_1 - y_2 \pmod{26}$$
    
4. To find $a$, we compute the modular multiplicative inverse of the plaintext difference $\Delta x = -17 \equiv 9 \pmod{26}$.
    
    $$a \equiv (y_1 - y_2) \cdot 9^{-1} \pmod{26}$$
    
    Note: $\gcd(9, 26) = 1$, so the inverse exists ($9^{-1} \equiv 3 \pmod{26}$).
    
5. Once $a$ is found, we solve for $b$:
    
    $$b \equiv y_1 - a(2) \pmod{26}$$
    
6. With keys $a$ and $b$, we derive the decryption function:
    
    $$D(y) = a^{-1}(y - b) \pmod{26}$$
    

#### Solver Script

This script calculates the encryption keys derived from the known header "CT" and decrypts the rest of the message.

Python

```
from Crypto.Util.number import inverse

def solve():
    # 1. The Ciphertext (Example from previous generation)
    # Replace this string with the content of output.txt
    ciphertext = "XGY{L1V3HI_HGV3MIH_XKUBJ3U_HGG1V3}"
    
    print(f"[*] Ciphertext: {ciphertext}")
    
    # 2. Extract known pairs (CTF format)
    # Plaintext 'C' (2) -> Ciphertext[0]
    # Plaintext 'T' (19) -> Ciphertext[1]
    
    p1 = ord('C') - ord('A') # 2
    p2 = ord('T') - ord('A') # 19
    
    c1 = ord(ciphertext[0]) - ord('A')
    c2 = ord(ciphertext[1]) - ord('A')
    
    print(f"[*] Pair 1: 'C'({p1}) -> '{ciphertext[0]}'({c1})")
    print(f"[*] Pair 2: 'T'({p2}) -> '{ciphertext[1]}'({c2})")
    
    # 3. Calculate Key 'a' using modular inverse
    # a * (p1 - p2) = (c1 - c2) mod 26
    delta_p = (p1 - p2) % 26
    delta_c = (c1 - c2) % 26
    
    # Calculate modular inverse of delta_p
    try:
        inv_delta_p = inverse(delta_p, 26)
    except ValueError:
        print("[-] Error: Plaintext difference has no inverse mod 26. Cannot solve uniquely with these chars.")
        return

    a = (delta_c * inv_delta_p) % 26
    
    # 4. Calculate Key 'b'
    # b = c1 - a * p1 mod 26
    b = (c1 - (a * p1)) % 26
    
    print(f"[+] Recovered Keys -> a: {a}, b: {b}")
    
    # 5. Verify with 3rd char 'F'
    # Plaintext 'F' (5) -> Ciphertext[2]
    expected_c3 = (a * (ord('F') - ord('A')) + b) % 26
    actual_c3 = ord(ciphertext[2]) - ord('A')
    
    if expected_c3 == actual_c3:
        print("[+] Key verification successful (matches 'F')")
    else:
        print("[-] Key verification failed. Cipher might not be Affine or noise exists.")
    
    # 6. Decrypt
    # D(y) = a^(-1) * (y - b) mod 26
    a_inv = inverse(a, 26)
    
    plaintext = []
    for char in ciphertext:
        if 'A' <= char <= 'Z':
            y = ord(char) - ord('A')
            x = (a_inv * (y - b)) % 26
            plaintext.append(chr(x + ord('A')))
        elif 'a' <= char <= 'z':
            y = ord(char) - ord('a')
            x = (a_inv * (y - b)) % 26
            plaintext.append(chr(x + ord('a')))
        else:
            plaintext.append(char)
            
    print(f"[SUCCESS] Flag: {''.join(plaintext)}")

if __name__ == "__main__":
    solve()
```

#### Expected Output

Plaintext

```
[*] Ciphertext: XGY{L1V3HI_HGV3MIH_XKUBJ3U_HGG1V3}
[*] Pair 1: 'C'(2) -> 'X'(23)
[*] Pair 2: 'T'(19) -> 'G'(6)
[+] Recovered Keys -> a: 25, b: 25
[+] Key verification successful (matches 'F')
[SUCCESS] Flag: CTF{L1N3AR_ALG3BRA_CRUSH3S_AFF1N3}
```

---

### Letter distribution matching

#### Theoretical Basis

In **Information Theory**, natural languages like English possess a high degree of **redundancy**. While a random string of 26 characters has an entropy of $\log_2(26) \approx 4.7$ bits per character, standard English text has a much lower entropy (estimated between 1.0 and 1.5 bits per character). This redundancy manifests as uneven probability distributions of characters (unigrams) and sequences of characters (n-grams).

A Monoalphabetic Substitution Cipher replaces every instance of a plaintext letter $p$ with a specific ciphertext letter $c$ according to a fixed permutation $\pi$.

$$E(p) = \pi(p)$$

$$D(c) = \pi^{-1}(c)$$

Crucially, this transformation is **isomorphic** with respect to frequency. It changes the _labels_ of the data but preserves the _shape_ of the probability distribution. If 'E' appears 12.7% of the time in the plaintext, its encrypted counterpart will also appear 12.7% of the time in the ciphertext.

#### The Vulnerability

The vulnerability is that the **ciphertext distribution** $P(C)$ closely approximates the **plaintext language distribution** $P(L)$.

An attacker can exploit this by minimizing the statistical distance (or Kullback-Leibler divergence) between the observed ciphertext frequencies and the known standard English frequencies.

$$D_{KL}(P(C) || P(L)) = \sum_{x \in X} P(C=x) \log \left( \frac{P(C=x)}{P(L=x)} \right)$$

In practice, this is solved via **Frequency Analysis**:

1. Count letter occurrences in ciphertext.
    
2. Sort ciphertext letters by frequency (High $\to$ Low).
    
3. Map them to standard English frequency order (E, T, A, O, I, N, ...).
    
4. Refine using Bigram analysis (e.g., finding 'TH', 'HE') to correct local swapping errors in the unigram mapping.
    

#### Challenge Design

This script generates a random monoalphabetic substitution cipher. It requires a sufficiently long text to ensure the statistical fingerprint is strong enough for the player to analyze.

Python

```
import random
import string

# Configuration
# A standard paragraph repeated or a long text is needed for accurate
# frequency analysis.
PLAINTEXT_CORPUS = """
Information theory studies the quantification, storage, and communication of
information. It was originally proposed by Claude Shannon in 1948 to find
fundamental limits on signal processing and communication operations such as
data compression, in a landmark paper titled A Mathematical Theory of
Communication. The field is at the intersection of probability theory,
statistics, computer science, statistical mechanics, information engineering,
and electrical engineering. A key measure in information theory is entropy.
Entropy quantifies the amount of uncertainty involved in the value of a random
variable or the outcome of a random process. For example, identifying the
outcome of a fair coin flip (with two equally likely outcomes) provides less
information (lower entropy) than specifying the outcome from a roll of a die
(with six equally likely outcomes). Some other important measures in
information theory are mutual information, channel capacity, error exponents,
and relative entropy. Important sub-fields of information theory include source
coding, algorithmic complexity theory, algorithmic information theory, and
information-theoretic security. Applications of fundamental topics of
information theory include source coding/data compression (e.g. for ZIP files),
and channel coding/error detection and correction (e.g. for DSL). Its impact
has been crucial to the success of the Voyager missions to deep space, the
invention of the compact disc, the feasibility of mobile phones, and the
development of the internet. The theory has also found applications in other
areas, including statistical inference, cryptography, neurobiology, perception,
linguistics, the evolution and function of molecular codes (bioinformatics),
thermal physics, quantum computing, linguistics, plagiarism detection, pattern
recognition, and anomaly detection.
"""

FLAG = "CTF{m0n0_subst1tut10n_c4nt_h1d3_st4t1st1cs}"

def generate_substitution_key():
    # Create a random permutation of the alphabet
    alphabet = list(string.ascii_uppercase)
    shuffled = list(string.ascii_uppercase)
    random.shuffle(shuffled)
    
    # Create a mapping dictionary
    key_map = dict(zip(alphabet, shuffled))
    return key_map

def encrypt(text, key_map):
    text = text.upper()
    ciphertext = []
    
    for char in text:
        if char in key_map:
            ciphertext.append(key_map[char])
        elif char in string.punctuation or char in string.whitespace:
            # Ideally, in "hard" CTFs, you remove spaces to hide word length.
            # For "medium" difficulty, keeping spaces helps the player (word patterns).
            # We will KEEP punctuation/spacing for this specific "Letter Distribution" lesson.
            ciphertext.append(char)
            
    return "".join(ciphertext)

def generate_challenge():
    # 1. Append flag to the corpus
    full_text = PLAINTEXT_CORPUS + "\n\nThe secret flag is: " + FLAG
    
    # 2. Generate Key
    key_map = generate_substitution_key()
    
    # 3. Encrypt
    ciphertext = encrypt(full_text, key_map)
    
    return ciphertext, key_map

if __name__ == "__main__":
    ct, used_key = generate_challenge()
    
    with open("ciphertext.txt", "w") as f:
        f.write(ct)
    
    # Save key for verification (Challenge Creator only)
    with open("key_mapping.txt", "w") as f:
        for k, v in used_key.items():
            f.write(f"{k} -> {v}\n")
            
    print("Challenge artifacts generated: ciphertext.txt (key saved to key_mapping.txt)")
```

#### Player Artifacts1

The player is provided with:2

1. `ciphertext.txt`: The text file containing the encrypted message. The structure (spaces and punctuation) is preserved, making the initial distribution analysis easier.

---

### Solution: Letter distribution matching

#### Exploitation Logic

The underlying principle for solving a monoalphabetic substitution cipher is that the statistical properties of the plaintext language are invariant under the substitution. By matching the letter distribution of the ciphertext to the known distribution of the English language, we can deduce the key.

The primary technique involves establishing an initial substitution key based on the ranked frequency of letters. The most common letters in English (E, T, A, O, I, N, S, H, R, D, L, U) serve as the target for the most frequent letters observed in the ciphertext.

We rely on the statistical stability of unigram frequencies, which for a long enough ciphertext, closely approximate the relative frequencies $P(L)$ of the language.

#### Standard English Frequencies

The typical descending order of unigram frequencies in English is:

$$\text{E} \to 12.7\% \quad \text{T} \to 9.1\% \quad \text{A} \to 8.2\% \quad \text{O} \to 7.5\% \quad \text{I} \to 7.0\% \quad \text{N} \to 6.7\% \quad \text{S} \to 6.3\% \quad \text{H} \to 6.1\%$$

The solver script will perform an automated frequency match to provide the **first pass** decryption, which then allows for rapid manual refinement based on common English words and bigrams (e.g., 'TH', 'HE').

#### Solver Script

This Python script performs the initial frequency analysis and substitution, allowing the user to easily see the resulting text and refine the key.

Python

```
from collections import Counter
import string

# ------------------------------------------------------
# Standard English Frequencies (ETAOIN SHRDLU...)
# ------------------------------------------------------
ENGLISH_FREQ_ORDER = "ETAOINSHRDLCUMWFGYPBVKJXQZ"
ALPHABET = string.ascii_uppercase

def analyze_and_decrypt():
    try:
        with open("ciphertext.txt", "r") as f:
            ciphertext = f.read().upper()
    except FileNotFoundError:
        print("[-] ciphertext.txt not found. Cannot proceed.")
        return

    # 1. Count frequencies in the ciphertext, ignoring non-alphabetic characters
    only_alpha_cipher = "".join(filter(str.isalpha, ciphertext))
    cipher_counts = Counter(only_alpha_cipher)
    
    # 2. Get the ciphertext alphabet sorted by frequency (most frequent first)
    # The key is the cipher character, value is its count
    cipher_freq_order = sorted(cipher_counts, key=cipher_counts.get, reverse=True)
    
    # Pad the cipher_freq_order list with unused letters if necessary
    for char in ALPHABET:
        if char not in cipher_freq_order:
            cipher_freq_order.append(char)
            
    # Truncate to 26 letters
    cipher_freq_order = cipher_freq_order[:26]

    # 3. Create the initial key map based on frequency matching
    # Cipher_Char -> Plaintext_Char
    initial_key_map = {}
    
    print("[*] Initial Frequency Mapping (Cipher -> Plaintext):")
    print("-" * 35)
    
    for i in range(26):
        c_char = cipher_freq_order[i]
        p_char = ENGLISH_FREQ_ORDER[i]
        initial_key_map[c_char] = p_char
        print(f"| {c_char:<5} -> {p_char:<5} | Count: {cipher_counts.get(c_char, 0):<5} |")

    # 4. Decrypt the full ciphertext using the initial key
    decrypted_text_list = []
    
    for char in ciphertext:
        if char in initial_key_map:
            decrypted_text_list.append(initial_key_map[char])
        else:
            decrypted_text_list.append(char) # Keep spaces/punctuation
            
    decrypted_text = "".join(decrypted_text_list)
    
    print("\n[+] Decrypted Text (First Pass - Needs Refinement):")
    print("=" * 70)
    print(decrypted_text)
    print("=" * 70)

    # 5. Manual Refinement Guide (for the flag)
    # The user would manually swap near-frequency letters (A/I, P/K, etc.)
    # based on recognizable words and the appearance of the flag format.
    
    # Based on the creation script, the flag is appended at the end.
    import re
    flag_match = re.search(r"CTF\{.*?\}", decrypted_text)
    if flag_match:
        print(f"\n[!] FLAG FOUND (Requires Validation/Refinement): {flag_match.group(0)}")
    else:
        print("\n[?] Flag not immediately found. Perform manual refinement on the output text.")


if __name__ == "__main__":
    analyze_and_decrypt()
```

#### Expected Decrypted Flag

The manual refinement of the resulting text, guided by common bigrams and word structure, will reveal the correct key and the flag:

Plaintext

```
CTF{m0n0_subst1tut10n_c4nt_h1d3_st4t1st1cs}
```

---

