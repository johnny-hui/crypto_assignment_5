"""
Description:
This Python file contains functions to generate data (graphs) and perform avalanche analysis.
"""
import secrets
import string
from utility.constants import AVALANCHE_ANALYSIS_PROMPT, AVALANCHE_ANALYSIS_USER_INPUT, ECB, AVALANCHE_TASK_SKAC_TITLE, \
    AVALANCHE_TASK_SPAC_TITLE
from utility.utilities import get_user_command_option

# CONSTANTS
MAX_BIT_CHANGE = 10
NUMBER_DICT = {
    1: "First",
    2: "Second",
    3: "Third",
    4: "Fourth",
    5: "Fifth",
    6: "Sixth",
    7: "Seventh",
    8: "Eighth",
    9: "Ninth",
    10: "Tenth",
}


def __print_experiment_info(control: list, experiment: list,
                            criteria: str, exp_num: int):
    if criteria == "SPAC":
        print("=" * 80)
        print("Task:", AVALANCHE_TASK_SPAC_TITLE.format(exp_num + 1))
        print("Original Plaintext (in Binary):")
        print(string_to_binary(control[0]))
        print("Modified Plaintext (in Binary):")
        print(string_to_binary(experiment[0]))
        print(f"Plaintext: {experiment[0]}")
        print(f"Key: {control[-1]}")  # => Key is appended as last element
        print("=" * 80)
    else:
        print("=" * 80)
        print("Task:", AVALANCHE_TASK_SKAC_TITLE.format(exp_num, NUMBER_DICT[exp_num + 1]))
        print("Original Key (in Binary): ", string_to_binary(control[-1]))
        print("Modified Key (in Binary): ", string_to_binary(experiment[exp_num][-1]))
        print("Plain Text:", control[0])
        print("Key:", experiment[-1])
        print("=" * 80)


def generate_random_string(block_size: int):
    """
    Randomly generates a random string of length
    block_size.

    @param block_size:
        An integer that represents the block size

    @return: random_string
        A string of random characters (64-bits; 8 char)
    """
    # Define a set of all possible ASCII characters
    alphabet = string.ascii_letters + string.digits + string.punctuation

    # Generate a random string based on the block size
    random_string = ''.join(secrets.choice(alphabet) for _ in range(block_size))
    return random_string


def string_to_binary(input_string: str):
    """
    Converts each character of the input_string
    to their 8-bit representation and concatenates
    it to form a binary string.

    @param input_string:
        A string of characters

    @return: binary_string
        A string containing a binary sequence of bits
    """
    return ''.join(format(ord(char), '08b') for char in input_string)


def binary_to_string(binary_string: str):
    """
    Converts a binary string back to a plaintext string
    of ASCII characters.

    @param binary_string:
        A string containing

    @return: plaintext_string
        A string containing ASCII characters
    """
    # Split the binary string into 8-bit chunks
    chunks = [binary_string[i:i + 8] for i in range(0, len(binary_string), 8)]

    # Convert each chunk to an integer and back to their corresponding character
    chars = [chr(int(chunk, 2)) for chunk in chunks]

    # Concatenate the characters to form the string
    return ''.join(chars)


def calculate_bit_differences(string_1: str, string_2: str):
    """
    Takes two strings, converts them into binary,
    and returns the bit differences between them.

    @param string_1:
        A string of characters

    @param string_2:
        A string of characters

    @return bit_difference:
        The bit difference between the input two strings (int)
    """
    # Convert both strings into their binary representations
    b1 = string_to_binary(string_1)
    b2 = string_to_binary(string_2)

    # Iterate and sum the differing bits
    bit_difference = sum(b1[i] != b2[i] for i in range(len(b1)))
    return bit_difference


def get_avalanche_criteria():
    """
    Prompts user for an avalanche criteria (SPAC or SKAC).

    @return: criteria
        A string containing the criteria (SPAC or SKAC)
    """
    while True:
        criteria = input("[+] AVALANCHE ANALYSIS - Enter a criteria to evaluate (SPAC, SKAC or 'q' to quit): ").upper()
        if criteria == 'Q':
            return None
        if criteria in ('SPAC', 'SKAC'):
            return criteria
        print("[+] An invalid criteria option was provided; please try again.")


def get_avalanche_user_plaintext(block_size: int):
    """
    Prompts the user to provide a string of size
    'block_size'.

    @param block_size:
        An integer representing the block size

    @return: plaintext
        A string containing the user's plaintext message
    """
    while True:
        plaintext = input(AVALANCHE_ANALYSIS_USER_INPUT)
        if len(plaintext) == block_size:
            return plaintext
        print(f"[+] The provided plaintext message is not exactly {block_size} characters in length;"
              f" please try again.")


def change_bits_from_msb(binary_string: str, num_bits: int):
    """
    Changes an X number of bits starting from the
    most significant bit (MSB) position.

    @param binary_string:
        A string of bits

    @param num_bits:
        An integer that represents the number
        of bits to change

    @return: ''.join(binary_list)
        A string containing the new binary string
    """
    # Convert the binary string to a list of characters
    binary_list = list(binary_string)

    # Flip the bits starting from the MSB
    for i in range(num_bits):
        binary_list[i] = '0' if binary_list[i] == '1' else '1'

    # Convert the list back to a string
    return ''.join(binary_list)


def perform_experiment(experiments: list, criteria: str,
                       cipher: object, payload: str):
    if criteria == 'SPAC':
        for i in range(MAX_BIT_CHANGE):
            new_plaintext_binary = change_bits_from_msb(payload, i + 1)
            new_plaintext = binary_to_string(new_plaintext_binary)
            experiments.append(cipher.encrypt(new_plaintext, verbose=True))

    if criteria == 'SKAC':
        print("TODO")


def _analyze_experiments(experiments: list, control: list,
                         criteria: string, UserViewModel: object = None,
                         cipher: object = None):
    """
    Analyzes the avalanche effect by calculating
    the bit differences of each intermediate ciphertext
    based on a SPAC or SKAC criteria.

    @param experiments:
        A list containing experimental group data

    @param control:
        A list containing control group data

    @param criteria:
        A string representing the criteria to analyze (SPAC, SKAC)

    @param UserViewModel:
        A reference to UserViewModel object
        (optional; only used for SKAC)

    @param cipher:
        A reference to a CustomCipher object
        (optional; only used for SKAC)

    @return:
    """
    for i, experiment in enumerate(experiments):
        __print_experiment_info(control, experiment, criteria, exp_num=i)

        # SLICE: Exclude the first and last elements (original block, key)
        sliced_control = control[1:-1]
        sliced_experiment = experiment[1:-1]

        # Get final ciphertext index
        final_index = len(sliced_control) - 1

        # Iterate through the rounds (and perform bit difference)
        for round_num, (control_cipher, exp_cipher) in enumerate(zip(sliced_control, sliced_experiment)):
            if round_num == final_index:
                print("Final Ciphertext (Original):   {}".format(string_to_binary(control_cipher)))
                print("Final Ciphertext (Experiment): {}".format(string_to_binary(exp_cipher)))
                bit_diff = calculate_bit_differences(control_cipher, exp_cipher)
                print(f"Bit difference: {bit_diff}")
            else:
                print("[+] Round {} Bit Difference".format(round_num + 1))

                # Get Original/Experiment Intermediate Ciphertexts (convert to binary)
                control_round_ciphertext = control_cipher
                exp_round_ciphertext = exp_cipher
                control_round_ciphertext_binary = string_to_binary(control_round_ciphertext)
                exp_round_ciphertext_binary = string_to_binary(exp_round_ciphertext)

                # Print the intermediate ciphertexts (in binary)
                print("\tOriginal Intermediate Ciphertext:")
                print(f"\t{control_round_ciphertext_binary}")
                print("\tModified Intermediate Ciphertext:")
                print(f"\t{exp_round_ciphertext_binary}")

                # Calculate Round Bit Differences
                bit_diff = calculate_bit_differences(control_round_ciphertext_binary,
                                                     exp_round_ciphertext_binary)
                print(f"\tNumber of bit differences: {bit_diff}\n")


def analyze_avalanche_effect(UserViewModel: object, cipher: object):
    """
    Analyzes the avalanche effect (~50% bit differences in
    ciphertext when bit changes are made in plaintext
    or key).

    @param UserViewModel:
        A reference to the calling class object (UserViewModel)

    @param cipher:
        A CustomCipher object

    @return analysis_results:
        A dictionary containing the results of the avalanche effect
    """
    experimental_group = []  # Group with bit changes applied

    # Switch to ECB mode for avalanche analysis
    print("[+] AVALANCHE ANALYSIS: Now switching cipher to ECB mode...")
    cipher.mode = ECB

    # Get criteria from user
    criteria = get_avalanche_criteria()

    # Perform user command
    if criteria is not None:
        option = get_user_command_option(opt_range=tuple(range(3)),
                                         msg=AVALANCHE_ANALYSIS_PROMPT)
        if option == 0:  # Quit
            return None

        if option == 1:  # Input own string
            plaintext = get_avalanche_user_plaintext(cipher.block_size)
            plaintext_binary = string_to_binary(plaintext)
            print(f"[+] Now performing avalanche analysis ({criteria}) on the following plaintext -> {plaintext}")

            # Gather data for the control group (no bit changes applied)
            control = cipher.encrypt(plaintext, verbose=True)

            if criteria == "SPAC":
                # Gather data for bit changes in the plaintext
                perform_experiment(experimental_group, criteria, cipher, payload=plaintext_binary)

                # Analyze the experiment data
                _analyze_experiments(experimental_group, control, criteria)

            if criteria == "SKAC":
                UserViewModel.save_cipher_state()

        if option == 2:  # Generate plaintext
            plaintext = generate_random_string(cipher.block_size)
            plaintext_binary = string_to_binary(plaintext)
            print(f"[+] Now performing avalanche analysis ({criteria}) on the following plaintext -> {plaintext}")

            # Gather data for the control group (no bit changes applied)
            control = cipher.encrypt(plaintext, verbose=True)

            if criteria == "SPAC":
                # Gather data for bit changes in the plaintext
                perform_experiment(experimental_group, criteria, cipher, payload=plaintext_binary)

                # Analyze the experiment data
                _analyze_experiments(experimental_group, control, criteria)

            if criteria == "SKAC":
                UserViewModel.save_cipher_state()

