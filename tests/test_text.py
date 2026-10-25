import unittest
from unittest.mock import patch

from src.crypto import Parameters, elgamal


class TextTests(unittest.TestCase):
    def setUp(self):
        self.parameters = Parameters(467, 2)
        self.private = 6
        self.public = elgamal.generate_public_key(self.parameters, self.private)

    def test_utf8_round_trips(self):
        for message in ["hello", "Halo dunia", "  hello  ", "", "123", "\x00", "café 🌏", "你好", "a\nb"]:
            with self.subTest(message=message):
                ciphertext = elgamal.encrypt_text(self.parameters, self.public, message)
                self.assertEqual(len(ciphertext), len(message.encode("utf-8")))
                self.assertEqual(
                    elgamal.decrypt_text(self.parameters, self.private, ciphertext), message
                )

    def test_every_byte_is_encoded_as_nonzero_with_fresh_randomness(self):
        with patch.object(elgamal, "encrypt", return_value=(2, 3)) as encrypt:
            elgamal.encrypt_text(self.parameters, self.public, "\x00hello")
        self.assertEqual([call.args[2] for call in encrypt.call_args_list], [1, 105, 102, 109, 109, 112])
        with patch.object(elgamal, "generate_private_key", side_effect=[3, 4]) as random_key:
            ciphertext = elgamal.encrypt_text(self.parameters, self.public, "aa")
        self.assertEqual(random_key.call_count, 2)
        self.assertNotEqual(ciphertext[0], ciphertext[1])

    def test_reject_invalid_parameters_ciphertext_and_utf8(self):
        for action in [
            lambda: elgamal.encrypt_text(Parameters(23, 5), 8, "hello"),
            lambda: elgamal.decrypt_text(Parameters(23, 5), 6, []),
            lambda: elgamal.decrypt_text(self.parameters, self.private, "bad"),
            lambda: elgamal.decrypt_text(self.parameters, self.private, [(2, 0)]),
            lambda: elgamal.decrypt_text(self.parameters, self.private, [(2, 467)]),
            lambda: elgamal.decrypt_text(self.parameters, self.private, [
                elgamal.encrypt(self.parameters, self.public, 256)
            ]),
        ]:
            with self.assertRaises(ValueError):
                action()
        with self.assertRaises(TypeError):
            elgamal.encrypt_text(self.parameters, self.public, 123)


if __name__ == "__main__":
    unittest.main()
