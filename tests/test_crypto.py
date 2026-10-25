import unittest
from unittest.mock import patch

from src.crypto import Parameters, diffie_hellman, elgamal, generate_parameters
from src.crypto.number_theory import (
    extended_gcd,
    find_primitive_root,
    generate_prime,
    is_prime,
    is_primitive_root,
    modular_inverse,
    modular_power,
    prime_factors,
)


class NumberTheoryTests(unittest.TestCase):
    def test_modular_power_against_builtin(self):
        for base in range(-5, 10):
            for exponent in range(12):
                for modulus in range(2, 25):
                    self.assertEqual(
                        modular_power(base, exponent, modulus),
                        pow(base, exponent, modulus),
                    )

    def test_extended_gcd_identity_and_inverse(self):
        for a, b, expected in [(240, 46, 2), (-15, 6, 3), (15, -6, 3),
                               (0, 7, 7), (7, 0, 7), (0, 0, 0)]:
            divisor, x, y = extended_gcd(a, b)
            self.assertEqual(divisor, expected)
            self.assertEqual(a * x + b * y, divisor)
        self.assertEqual(modular_inverse(6, 23), 4)
        self.assertEqual(modular_inverse(-3, 11), 7)
        with self.assertRaises(ValueError):
            modular_inverse(6, 12)

    def test_prime_testing_and_factorization(self):
        expected_primes = {2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37,
                           41, 43, 47}
        for number in range(-3, 50):
            self.assertEqual(is_prime(number), number in expected_primes)
        for composite in [121, 341, 561, 1105]:
            self.assertFalse(is_prime(composite))
        self.assertEqual(prime_factors(1), set())
        self.assertEqual(prime_factors(360), {2, 3, 5})
        self.assertEqual(prime_factors(23), {23})

    def test_prime_generation_and_primitive_roots(self):
        for bits in [2, 3, 8, 16]:
            prime = generate_prime(bits)
            self.assertEqual(prime.bit_length(), bits)
            self.assertTrue(is_prime(prime))
        for prime in [2, 3, 5, 7, 23, 47]:
            generator = find_primitive_root(prime)
            self.assertTrue(is_primitive_root(generator, prime))
            self.assertEqual(
                {pow(generator, exponent, prime) for exponent in range(1, prime)},
                set(range(1, prime)),
            )
        self.assertFalse(is_primitive_root(4, 23))
        self.assertFalse(is_primitive_root(0, 23))

    def test_invalid_math_inputs(self):
        for function, arguments in [
            (modular_power, (2, -1, 7)),
            (modular_power, (2, 3, 1)),
            (modular_inverse, (2, 0)),
            (generate_prime, (1,)),
            (prime_factors, (0,)),
            (find_primitive_root, (15,)),
            (is_primitive_root, (2, 15)),
        ]:
            with self.subTest(function=function.__name__, arguments=arguments):
                with self.assertRaises(ValueError):
                    function(*arguments)
        for value in [True, 2.5, "23", None]:
            with self.assertRaises(TypeError):
                is_prime(value)


class AlgorithmTests(unittest.TestCase):
    def setUp(self):
        self.parameters = Parameters(p=23, g=5)

    def test_diffie_hellman_known_answer(self):
        alice_public = diffie_hellman.generate_public_key(self.parameters, 6)
        bob_public = diffie_hellman.generate_public_key(self.parameters, 15)
        self.assertEqual(alice_public, 8)
        self.assertEqual(bob_public, 19)
        self.assertEqual(
            diffie_hellman.compute_shared_secret(self.parameters, 6, bob_public), 2
        )
        self.assertEqual(
            diffie_hellman.compute_shared_secret(self.parameters, 15, alice_public), 2
        )

    def test_diffie_hellman_all_small_private_keys(self):
        for alice in range(1, 22):
            for bob in range(1, 22):
                alice_public = diffie_hellman.generate_public_key(self.parameters, alice)
                bob_public = diffie_hellman.generate_public_key(self.parameters, bob)
                self.assertEqual(
                    diffie_hellman.compute_shared_secret(self.parameters, alice, bob_public),
                    diffie_hellman.compute_shared_secret(self.parameters, bob, alice_public),
                )

    def test_elgamal_known_answer(self):
        with patch.object(elgamal, "generate_private_key", return_value=3):
            ciphertext = elgamal.encrypt(self.parameters, 8, 10)
        self.assertEqual(ciphertext, (10, 14))
        self.assertEqual(elgamal.decrypt(self.parameters, 6, ciphertext), 10)

    def test_elgamal_all_small_keys_messages_and_ephemeral_keys(self):
        for private in range(1, 22):
            public = elgamal.generate_public_key(self.parameters, private)
            for ephemeral in range(1, 22):
                with patch.object(elgamal, "generate_private_key", return_value=ephemeral):
                    for message in range(23):
                        ciphertext = elgamal.encrypt(self.parameters, public, message)
                        self.assertEqual(
                            elgamal.decrypt(self.parameters, private, ciphertext), message
                        )

    def test_fresh_random_key_requested_for_each_encryption(self):
        with patch.object(elgamal, "generate_private_key", side_effect=[3, 4]) as random_key:
            first = elgamal.encrypt(self.parameters, 8, 10)
            second = elgamal.encrypt(self.parameters, 8, 10)
        self.assertEqual(random_key.call_count, 2)
        self.assertNotEqual(first, second)
        for ciphertext in [first, second]:
            self.assertEqual(elgamal.decrypt(self.parameters, 6, ciphertext), 10)

    def test_generated_parameters_and_random_key_round_trips(self):
        for _ in range(5):
            parameters = generate_parameters(bits=12)
            self.assertEqual(parameters.p.bit_length(), 12)
            self.assertTrue(is_primitive_root(parameters.g, parameters.p))
            alice, alice_public = diffie_hellman.generate_key_pair(parameters)
            bob, bob_public = diffie_hellman.generate_key_pair(parameters)
            self.assertTrue(1 <= alice <= parameters.p - 2)
            self.assertEqual(alice_public, pow(parameters.g, alice, parameters.p))
            self.assertEqual(
                diffie_hellman.compute_shared_secret(parameters, alice, bob_public),
                diffie_hellman.compute_shared_secret(parameters, bob, alice_public),
            )
            private, public = elgamal.generate_key_pair(parameters)
            for message in [0, 1, 42, parameters.p - 1]:
                self.assertEqual(
                    elgamal.decrypt(parameters, private, elgamal.encrypt(parameters, public, message)),
                    message,
                )

    def test_invalid_parameters_keys_messages_and_ciphertexts(self):
        for p, g in [(3, 2), (15, 2), (23, 4), (23, 1), (23, 23)]:
            with self.assertRaises(ValueError):
                Parameters(p, g)
        with self.assertRaises(ValueError):
            generate_parameters(2)
        for private in [0, -1, 22, 23]:
            with self.assertRaises(ValueError):
                diffie_hellman.generate_public_key(self.parameters, private)
            with self.assertRaises(ValueError):
                elgamal.decrypt(self.parameters, private, (10, 14))
        for public in [-1, 0, 1, 23]:
            with self.assertRaises(ValueError):
                diffie_hellman.compute_shared_secret(self.parameters, 6, public)
            with self.assertRaises(ValueError):
                elgamal.encrypt(self.parameters, public, 10)
        for message in [-1, 23, 100]:
            with self.assertRaises(ValueError):
                elgamal.encrypt(self.parameters, 8, message)
        for ciphertext in [(0, 14), (1, 14), (23, 14), (10, -1), (10, 23),
                           (), (10,), (10, 14, 2), [10, 14], None]:
            with self.assertRaises(ValueError):
                elgamal.decrypt(self.parameters, 6, ciphertext)
        with self.assertRaises(TypeError):
            elgamal.encrypt(self.parameters, 8, "hello")


if __name__ == "__main__":
    unittest.main()
