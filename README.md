# Diffie-Hellman and ElGamal

A college implementation from scratch, using only Python's standard library.
All algorithm functions live in `src/crypto`. There are no third-party
dependencies. Run commands from this project directory.

```sh
uv run python main.py
uv run python -m unittest discover -s tests -v
```

## Interactive CLI

Run `uv run python main.py` to open the menu:

The default public parameters are `p=467, g=2`, which support text messages.

1. Configure public parameters: use `(23, 5)`, generate a small prime, or
   enter your own prime and primitive root.
2. Run a Diffie-Hellman exchange with Alice and Bob. Enter private keys or
   press Enter for random keys; the CLI shows both public keys and secrets.
3. Create ElGamal keys with a chosen or random private key.
4. Encrypt an integer using the stored public key or one you enter.
5. Decrypt using the stored private key and ciphertext or values you enter.
6. Encrypt a text message, such as `hello`, into a hex string.
7. Decrypt text using the stored ciphertext or a hex string you paste.
0. Exit.

To encrypt `hello`, choose **3**, enter private key `6`, choose **6**, press
Enter for the stored public key, and type `hello` without surrounding quotes.
Choose **7** and press Enter twice to recover the original message. Spaces
and Unicode characters are preserved. Text input is one line per CLI prompt.

The CLI displays private keys for learning. Stored values last only for the
current session. Changing parameters clears the stored keys and ciphertexts;
creating new ElGamal keys clears the stored ciphertexts. Press Ctrl+C to exit
at any prompt. Parameters in the CLI are limited to 24 bits to keep trial
division practical.

For a known Diffie-Hellman example, first choose option 1, then option 1 again
to select `(23, 5)`. Select option 2 and enter `6` and `15`.
Both shared secrets will be `2`. To try ElGamal, select option 3, enter `6`,
then select option 4, press Enter for the public key, and enter message `10`.
Select option 5 and press Enter at its three prompts to recover `10`.

## Files

- `number_theory.py`: repeated-squaring modular exponentiation, extended
  Euclidean algorithm, modular inverse, trial-division primality testing,
  prime generation, prime factors, and primitive roots.
- `parameters.py`: validated public parameters `(p, g)` and random secret keys.
- `diffie_hellman.py`: key generation and shared-secret computation.
- `elgamal.py`: key generation, integer and text encryption, and decryption.
- `serialization.py`: convert ciphertext pairs to hex and back.

## Diffie-Hellman

Both parties use the same public prime `p` and generator `g`. Alice keeps `a`
secret and publishes `A = g^a mod p`. Bob keeps `b` secret and publishes
`B = g^b mod p`. They calculate `B^a mod p` and `A^b mod p`, respectively;
both results equal `g^(ab) mod p`.

```python
from src.crypto import Parameters, diffie_hellman

parameters = Parameters(p=23, g=5)
alice_private = 6
bob_private = 15
alice_public = diffie_hellman.generate_public_key(parameters, alice_private)
bob_public = diffie_hellman.generate_public_key(parameters, bob_private)
alice_secret = diffie_hellman.compute_shared_secret(
    parameters, alice_private, bob_public
)
bob_secret = diffie_hellman.compute_shared_secret(
    parameters, bob_private, alice_public
)
assert alice_secret == bob_secret == 2
```

For random keys, use `diffie_hellman.generate_key_pair(parameters)`. Key pairs
are always returned as `(private_key, public_key)`.

## ElGamal

The recipient's private key is `x`, and public key is `y = g^x mod p`.
Encryption chooses a fresh random `k`, then returns
`(c1, c2) = (g^k mod p, message * y^k mod p)`. Decryption calculates
`s = c1^x mod p` and recovers `message = c2 * s^(-1) mod p`.

```python
from src.crypto import Parameters, elgamal, generate_parameters

parameters = Parameters(p=23, g=5)
# Alternatively: parameters = generate_parameters(bits=16)
private_key, public_key = elgamal.generate_key_pair(parameters)
ciphertext = elgamal.encrypt(parameters, public_key, message=10)
assert elgamal.decrypt(parameters, private_key, ciphertext) == 10
```

Messages are integers from `0` to `p - 1`; larger values are rejected instead
of silently reduced. Signatures are outside this implementation.
A zero integer message always has `c2 = 0`, so its
value is exposed; the usual ElGamal message group is `1` through `p - 1`.

`elgamal.encrypt_text(parameters, public_key, message)` encodes a string as
UTF-8, adds 1 to each byte so every encoded value is nonzero, and encrypts
each value with a fresh random exponent. Text requires `p > 256`.
`elgamal.decrypt_text(parameters, private_key, ciphertext)` reverses these
steps. Ciphertexts are lists of integer pairs; the CLI displays them as hex
for copying and pasting. Each integer occupies the same number of bytes as
`p`, in big-endian order, with `c1` followed by `c2` for every pair. Use the
same parameters and recipient key when decrypting. Decryption rejects
malformed pairs, values outside
the byte range, and invalid UTF-8. A wrong key can still produce valid text:
textbook ElGamal does not provide integrity checking.

These are educational textbook algorithms. Trial division is suitable for
small classroom numbers; the default generated prime is only 16 bits.
The code is not constant-time, DH does not authenticate the parties or derive
an encryption key, and ElGamal does not authenticate ciphertexts. Use these
functions for studying the calculations, not protecting real data.
