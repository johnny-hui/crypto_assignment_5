"""
Description:
This Python file contains functions to generate data (graphs) and perform avalanche analysis.

"""
import os
import secrets
import string
from matplotlib import pyplot as plt
from utility.constants import AVALANCHE_ANALYSIS_SPAC_PROMPT, AVALANCHE_ANALYSIS_USER_INPUT, ECB, \
    AVALANCHE_TASK_SKAC_TITLE, \
    AVALANCHE_TASK_SPAC_TITLE, AVALANCHE_ANALYSIS_SKAC_PROMPT, SAVE_GRAPH_DIR, GRAPH_LABEL_SPAC, GRAPH_LABEL_SKAC, \
    AVALANCHE_ANALYSIS_USER_INPUT_KEY
from utility.utilities import get_user_command_option

# CONSTANTS
MAX_BIT_CHANGE = 10
NUMBER_DICT = {
    1: "First", 2: "Second",
    3: "Third", 4: "Fourth",
    5: "Fifth", 6: "Sixth",
    7: "Seventh", 8: "Eighth",
    9: "Ninth", 10: "Tenth",
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
        print("Task:", AVALANCHE_TASK_SKAC_TITLE.format(exp_num + 1, NUMBER_DICT[exp_num + 1]))
        print("Original Key (in Binary): ", string_to_binary(control[-1]))
        print("Modified Key (in Binary): ", string_to_binary(experiment[-1]))
        print("Plain Text:", control[0])
        print("Key:", experiment[-1])
        print("=" * 80)


def generate_graph(data: dict, criteria: str):
    """
    Generates a line graph for representation of the avalanche
    effect, and saves it to as a PNG file under 'data/graphs'
    directory.

    @param data:
        A dictionary containing experiment results

    @param criteria:
        A string representing the criteria (SPAC or SKAC)

    @return: None
    """
    # Create a figure and axis object
    fig, ax = plt.subplots(figsize=(10, 6))

    # Plot a line for each experiment from the results
    for key, value in data.items():
        rounds = [int(item[0]) for item in value]
        bit_diff = [item[3] for item in value]
        ax.plot(rounds, bit_diff, label=key)

    # Set labels and title (according to criteria)
    ax.set_xlabel('Rounds')
    ax.set_ylabel('Bit Difference')

    # Create directory to save graph
    if not os.path.exists(SAVE_GRAPH_DIR.format(criteria)):
        os.makedirs(SAVE_GRAPH_DIR.format(criteria))

    # Set title, legend and save graph
    criteria_label = "SPAC" if criteria == "SPAC" else "SKAC"
    ax.set_title(f'Avalanche Effect (Bit Difference per Round - {criteria_label})')
    legend_labels = GRAPH_LABEL_SPAC if criteria == "SPAC" else GRAPH_LABEL_SKAC
    ax.legend(legend_labels, loc='lower right')
    save_path = os.path.join(SAVE_GRAPH_DIR.format(criteria), f'avalanche_effect_plot_{criteria}.png')
    plt.savefig(save_path)
    print(f"[+] GRAPHS GENERATED: The graph has been saved under {save_path}")


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


def get_avalanche_user_input(block_size: int, input_type: str):
    """
    Prompts the user to provide a string of size block_size,
    which can be used as a key (SKAC) or plaintext (SPAC).

    @param block_size:
        An integer representing the block size

    @param input_type:
        A string to designate whether a plaintext
        or key should be entered

    @return: plaintext
        A string containing the user's plaintext message
    """
    while True:
        if input_type == 'plaintext':
            user_input = input(AVALANCHE_ANALYSIS_USER_INPUT)
        else:
            user_input = input(AVALANCHE_ANALYSIS_USER_INPUT_KEY)

        if len(user_input) == block_size:
            return user_input

        print(f"[+] The provided input is not exactly {block_size} characters in length; please try again.")


def flip_bits_from_msb(binary_string: str, num_bits: int):
    """
    Inverts an X number of bits starting from the
    most significant bit (MSB) position.

    @attention Use Case:
        This is used for avalanche plaintext
        analysis (SPAC) only

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


def flip_every_4th_bit(binary_string: str, num_bits: int):
    """
    Inverts the 4th bit for every group of four bits
    in the binary string (starting from MSB).

    @attention Use Case:
        This is used for avalanche key analysis
        (SKAC) only

    @param binary_string:
        A string of bits

    @param num_bits:
        An integer that represents the number
        of bits to change

    @return: ''.join(binary_list)
        A string containing the new binary string
    """
    # Modify the 4th bit in each 4-bit segment of the binary string
    binary_list = list(binary_string)

    for i in range(3, len(binary_string), 4):
        if num_bits == 0:
            break
        binary_list[i] = '0' if binary_list[i] == '1' else '1'
        num_bits -= 1

    return ''.join(binary_list)


def _perform_experiments(experiments: list, criteria: str,
                         cipher: object, binary_payload: str,
                         plaintext: str = None):
    """
    Performs bit change experiments on the plaintext
    (SPAC) or key (SKAC) for avalanche effect analysis.

    @param experiments:
        A list containing experimental group data

    @param criteria:
        A string representing the criteria to analyze (SPAC, SKAC)

    @param cipher:
        A reference to a CustomCipher object
        (optional; only used for SKAC)

    @param binary_payload:
        A string containing a binary sequence

    @param plaintext:
        An optional string only used for SKAC (default=None)

    @return: None
    """
    if criteria == 'SPAC':  # => Key stays constant
        for i in range(MAX_BIT_CHANGE):
            new_plaintext_binary = flip_bits_from_msb(binary_payload, num_bits=i + 1)
            new_plaintext = binary_to_string(new_plaintext_binary)
            experiments.append(cipher.encrypt(new_plaintext, verbose=True))

    if criteria == 'SKAC':  # => Plaintext stays constant
        for i in range(MAX_BIT_CHANGE):
            new_key_binary = flip_every_4th_bit(binary_payload, num_bits=i + 1)
            new_key = binary_to_string(new_key_binary)
            cipher.key = new_key
            cipher.process_subkey_generation(menu_option=1)
            experiments.append(cipher.encrypt(plaintext, verbose=True))


def _analyze_experiments(experiments: list, control: list, criteria: string):
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

    @return: results:
        A dictionary to store each experiment's results per analysis
    """
    results = {}

    for i, experiment in enumerate(experiments):
        experiment_results = []
        __print_experiment_info(control, experiment, criteria, exp_num=i)

        # SLICE: Exclude the first and last elements (original block, key)
        sliced_control = control[1:-1]
        sliced_experiment = experiment[1:-1]

        # Get final ciphertext index
        final_index = len(sliced_control) - 1

        # Iterate through the rounds for an experiment (and perform bit difference)
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
                bit_diff = calculate_bit_differences(control_round_ciphertext_binary, exp_round_ciphertext_binary)
                print(f"\tNumber of bit differences: {bit_diff}\n")

                # Save round results
                experiment_results.append([(round_num + 1), control_round_ciphertext, exp_round_ciphertext, bit_diff])

        # Save experiment results
        results[f"Experiment {i + 1}"] = experiment_results
    return results


def _perform_avalanche_spac(UserViewModel: object, criteria: str, option: int,
                            cipher: object, experimental_group: list):
    """
    Performs avalanche analysis on a cipher using the
    SPAC criteria.

    @param UserViewModel:
        A reference to the calling class object (UserViewModel)

    @param criteria:
        A string containing the criteria

    @param option:
        An integer indicating the option to perform

    @param cipher:
        A CustomCipher object

    @param experimental_group:
        A list to carry data for each experiment (bit changes)

    @return: None
    """
    if option == 0:  # Quit
        return None

    if option == 1:  # Input own string
        plaintext = get_avalanche_user_input(cipher.block_size, input_type='plaintext')
        plaintext_binary = string_to_binary(plaintext)
        print(f"[+] Now performing avalanche analysis ({criteria}) on the following plaintext -> {plaintext}")

    # Option 2 - Generate random plaintext string
    else:
        plaintext = generate_random_string(cipher.block_size)
        plaintext_binary = string_to_binary(plaintext)
        print(f"[+] Now performing avalanche analysis ({criteria}) with generated plaintext -> {plaintext}")

    # Save state since cipher changes to ECB mode
    UserViewModel.save_cipher_state()

    # Switch to ECB mode for avalanche analysis
    print("[+] AVALANCHE ANALYSIS: Now switching cipher to ECB mode...")
    cipher.mode = ECB

    # Gather data for the control group (no bit changes applied)
    control = cipher.encrypt(plaintext, verbose=True)

    # Gather data for the experimental group (bit changes in the plaintext)
    _perform_experiments(experimental_group, criteria, cipher, binary_payload=plaintext_binary)

    # Analyze the experiment data and generate graph
    results = _analyze_experiments(experimental_group, control, criteria)
    generate_graph(data=results, criteria=criteria)

    # Restore the previous state of the cipher
    UserViewModel.restore_cipher_state(cipher)


def _perform_avalanche_skac(UserViewModel: object, criteria: str, option: int,
                            cipher: object, experimental_group: list):
    """
    Performs avalanche analysis on a cipher using the
    SKAC criteria.

    @param UserViewModel:
        A reference to the calling class object (UserViewModel)

    @param criteria:
        A string containing the criteria

    @param option:
        An integer indicating the option to perform

    @param cipher:
        A CustomCipher object

    @param experimental_group:
        A list to carry data for each experiment (bit changes)

    @return: None
    """
    if option == 0:  # Quit
        return None

    if option == 1:  # Input own key
        key = get_avalanche_user_input(cipher.block_size, input_type="key")
        plaintext = get_avalanche_user_input(cipher.block_size, input_type="plaintext")
        print(f"[+] Now performing avalanche analysis ({criteria}) with the following initial key -> {key}")

    # Option 2 - Generate key
    else:
        key = generate_random_string(cipher.block_size)
        plaintext = generate_random_string(cipher.block_size)
        print(f"[+] Now performing avalanche analysis ({criteria}) with the generated key -> {key}")

    # Save cipher state since key & sub-keys change
    UserViewModel.save_cipher_state()

    # Switch to ECB mode for avalanche analysis
    print("[+] AVALANCHE ANALYSIS: Now switching cipher to ECB mode...")
    cipher.mode = ECB

    # Set new key to the cipher and generate new sub-keys
    cipher.key = key
    cipher.process_subkey_generation(menu_option=1)

    # Gather data for the control group (no bit changes applied)
    control = cipher.encrypt(plaintext, verbose=True)

    # Convert key to binary and gather data for bit changes in the plaintext
    key_binary = string_to_binary(key)
    _perform_experiments(experimental_group, criteria, cipher,
                         binary_payload=key_binary, plaintext=plaintext)

    # Analyze the experiment data and generate graph
    results = _analyze_experiments(experimental_group, control, criteria)
    generate_graph(data=results, criteria=criteria)

    # Restore the previous state of the cipher before key & sub-key change
    UserViewModel.restore_cipher_state(cipher)


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

    # Get criteria from user
    criteria = get_avalanche_criteria()

    # Perform user command
    if criteria == "SPAC":
        option = get_user_command_option(opt_range=tuple(range(3)), msg=AVALANCHE_ANALYSIS_SPAC_PROMPT)
        _perform_avalanche_spac(UserViewModel, criteria, option, cipher, experimental_group)

    if criteria == "SKAC":
        option = get_user_command_option(opt_range=tuple(range(3)), msg=AVALANCHE_ANALYSIS_SKAC_PROMPT)
        _perform_avalanche_skac(UserViewModel, criteria, option, cipher, experimental_group)
