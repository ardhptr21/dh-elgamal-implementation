import io
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from src.cli import main
from src.crypto import Parameters, elgamal
from src.crypto.serialization import ciphertext_to_hex


class CliTests(unittest.TestCase):
    def run_cli(self, answers, use_small_example=True):
        output = io.StringIO()
        if use_small_example:
            answers = ["1", "1", *answers]
        with patch("builtins.input", side_effect=answers), redirect_stdout(output):
            main()
        return output.getvalue()

    def test_known_diffie_hellman_exchange(self):
        output = self.run_cli(["2", "6", "15", "0"])
        self.assertIn("Alice public key A = 5^6 mod 23 = 8", output)
        self.assertIn("Bob public key B = 5^15 mod 23 = 19", output)
        self.assertIn("Alice shared secret = 19^6 mod 23 = 2", output)
        self.assertIn("Bob shared secret = 8^15 mod 23 = 2", output)
        self.assertIn("Shared secrets match: True", output)

    def test_elgamal_round_trip_with_stored_values(self):
        with patch("src.crypto.elgamal.generate_private_key", return_value=3):
            output = self.run_cli(["3", "6", "4", "", "10", "5", "", "", "", "0"])
        self.assertIn("Recipient public key y = 5^6 mod 23 = 8", output)
        self.assertIn("Ciphertext (c1, c2) = (10, 14)", output)
        self.assertIn("Recovered message = 10", output)

    def test_decrypt_manually_without_stored_values(self):
        output = self.run_cli(["5", "6", "10", "14", "0"])
        self.assertIn("Recovered message = 10", output)

    def test_invalid_inputs_are_retried(self):
        output = self.run_cli([
            "hello", "8", "2", "abc", "0", "6", "15",
            "4", "1", "8", "23", "-1", "10", "0",
        ])
        self.assertIn("Please enter a whole number.", output)
        self.assertIn("Please enter a number from 0 to 7.", output)
        self.assertIn("Please enter a whole number from 1 to 21.", output)
        self.assertIn("Please enter a number from 2 to 22.", output)
        self.assertIn("Please enter a number from 0 to 22.", output)
        self.assertIn("Ciphertext (c1, c2)", output)

    def test_custom_parameters_clear_previous_state(self):
        output = self.run_cli([
            "3", "6", "4", "", "10",
            "1", "3", "15", "2", "47", "5",
            "5", "6", "5", "10", "0",
        ])
        self.assertIn("Invalid parameters: prime must be prime", output)
        self.assertIn("Stored keys and ciphertext cleared.", output)
        self.assertIn("Public parameters: p=47, g=5", output)
        self.assertIn("Recovered message", output)

    def test_generated_parameters_and_random_private_keys(self):
        output = self.run_cli(["1", "2", "2", "8", "2", "", "", "0"])
        self.assertIn("Please enter a number from 3 to 24.", output)
        self.assertIn("Parameters updated.", output)
        self.assertIn("Shared secrets match: True", output)

    def test_parameter_back_preserves_saved_keys_and_ciphertext(self):
        output = self.run_cli([
            "3", "6", "4", "", "10", "1", "0", "5", "", "", "", "0",
        ])
        self.assertEqual(output.count("Stored keys and ciphertext cleared."), 1)
        self.assertIn("Recovered message = 10", output)

    def test_eof_and_keyboard_interrupt_exit_cleanly(self):
        for exception in [EOFError, KeyboardInterrupt]:
            with self.subTest(exception=exception):
                output = self.run_cli(["2", exception()])
                self.assertIn("Goodbye!", output)

    def test_text_round_trip_with_default_parameters(self):
        output = self.run_cli([
            "3", "6", "6", "", "  hello dunia!  ", "7", "", "", "0",
        ], use_small_example=False)
        self.assertIn("Public parameters: p=467, g=2", output)
        self.assertRegex(output, r"Text ciphertext \(hex\) = [0-9a-f]+\n")
        self.assertIn("Recovered text =   hello dunia!  ", output)

    def test_manual_text_ciphertext_and_invalid_input(self):
        parameters = Parameters(467, 2)
        public = elgamal.generate_public_key(parameters, 6)
        ciphertext = elgamal.encrypt_text(parameters, public, "hello")
        output = self.run_cli([
            "7", "6", "not hex", "00", "00020000", ciphertext_to_hex(parameters, ciphertext), "0",
        ], use_small_example=False)
        self.assertEqual(output.count("Cannot decrypt text:"), 3)
        self.assertIn("Recovered text = hello", output)

    def test_small_parameters_reject_text_without_crashing(self):
        output = self.run_cli(["6", "7", "0"])
        self.assertEqual(output.count("Text requires p greater than 256."), 2)


if __name__ == "__main__":
    unittest.main()
