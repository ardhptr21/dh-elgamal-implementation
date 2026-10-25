import secrets
from math import isqrt


def require_integer(value: int, name: str) -> None:
    if type(value) is not int:
        raise TypeError(f"{name} must be an integer")


def modular_power(base: int, exponent: int, modulus: int) -> int:
    require_integer(base, "base")
    require_integer(exponent, "exponent")
    require_integer(modulus, "modulus")
    if exponent < 0:
        raise ValueError("exponent must be nonnegative")
    if modulus <= 1:
        raise ValueError("modulus must be greater than 1")

    result = 1
    base = base % modulus
    while exponent > 0:
        if exponent % 2 == 1:
            result = (result * base) % modulus
        base = (base * base) % modulus
        exponent //= 2
    return result


def extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    require_integer(a, "a")
    require_integer(b, "b")
    old_r, r = abs(a), abs(b)
    old_x, x = 1, 0
    old_y, y = 0, 1

    while r != 0:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_x, x = x, old_x - quotient * x
        old_y, y = y, old_y - quotient * y

    if a < 0:
        old_x = -old_x
    if b < 0:
        old_y = -old_y
    return old_r, old_x, old_y


def modular_inverse(value: int, modulus: int) -> int:
    require_integer(value, "value")
    require_integer(modulus, "modulus")
    if modulus <= 1:
        raise ValueError("modulus must be greater than 1")
    divisor, x, _ = extended_gcd(value, modulus)
    if divisor != 1:
        raise ValueError("value has no inverse modulo modulus")
    return x % modulus


def is_prime(number: int) -> bool:
    require_integer(number, "number")
    if number < 2:
        return False
    if number == 2:
        return True
    if number % 2 == 0:
        return False
    for divisor in range(3, isqrt(number) + 1, 2):
        if number % divisor == 0:
            return False
    return True


def prime_factors(number: int) -> set[int]:
    require_integer(number, "number")
    if number < 1:
        raise ValueError("number must be positive")
    factors = set()
    divisor = 2
    while divisor * divisor <= number:
        while number % divisor == 0:
            factors.add(divisor)
            number //= divisor
        divisor += 1
    if number > 1:
        factors.add(number)
    return factors


def generate_prime(bits: int = 16) -> int:
    require_integer(bits, "bits")
    if bits < 2:
        raise ValueError("bits must be at least 2")
    while True:
        candidate = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if is_prime(candidate):
            return candidate


def is_primitive_root(generator: int, prime: int) -> bool:
    require_integer(generator, "generator")
    if not is_prime(prime):
        raise ValueError("prime must be prime")
    if not 1 <= generator < prime:
        return False
    return all(
        modular_power(generator, (prime - 1) // factor, prime) != 1
        for factor in prime_factors(prime - 1)
    )


def find_primitive_root(prime: int) -> int:
    if not is_prime(prime):
        raise ValueError("prime must be prime")
    factors = prime_factors(prime - 1)
    for generator in range(1, prime):
        if all(
            modular_power(generator, (prime - 1) // factor, prime) != 1
            for factor in factors
        ):
            return generator
    raise ValueError("no primitive root found")
