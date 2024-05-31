import copy
import select
import sys
from models.CustomCipher import CustomCipher
from utility.avalanche import analyze_avalanche_effect
from utility.constants import USER_INPUT_PROMPT, USER_MENU_TITLE, USER_MENU_COLUMNS, \
    MIN_MENU_ITEM_VALUE, MAX_MENU_ITEM_VALUE, USER_MENU_OPTIONS_LIST
from utility.utilities import get_user_menu_option, make_table, change_mode, change_main_key, regenerate_sub_keys, \
    encrypt, view_pending_operations, decrypt, print_config


class UserViewModel:
    """A ViewModel class for an interactable user menu.

    Attributes:
        table - A table containing several user menu options
        cipher - A CustomCipher object
        terminate - A boolean for the termination of the application
        pending_operations - A dictionary (cache) that stores pending operations for the current state
        cipher_state - A list to store the cipher state (used for avalanche analysis (SKAC) key changes)
    """
    def __init__(self, *args):
        self.table = make_table(USER_MENU_TITLE, USER_MENU_COLUMNS, USER_MENU_OPTIONS_LIST)
        self.cipher = CustomCipher(key=args[0], mode=args[1], subkey_flag=args[2])
        self.terminate = False
        self.pending_operations = {}  # Format => {Encrypted_Format: (mode, cipher_text/path_to_file, IV)}
        self.cipher_state = []

    def start(self):
        """
        Starts the application.
        @return: None
        """
        self.__menu()

    def __menu(self):
        """
        Displays the menu and handles user input
        using select().

        @return: None
        """
        inputs = [sys.stdin]
        print("=" * 160)
        print(self.table)
        print(USER_INPUT_PROMPT)

        while not self.terminate:
            readable, _, _ = select.select(inputs, [], [])

            # Get User Command from the Menu and perform the task
            for fd in readable:
                if fd == sys.stdin:
                    command = get_user_menu_option(fd, MIN_MENU_ITEM_VALUE, MAX_MENU_ITEM_VALUE)

                    if command == 1:
                        encrypt(self, self.cipher)

                    if command == 2:
                        decrypt(self, self.cipher)

                    if command == 3:
                        analyze_avalanche_effect(self, self.cipher)

                    if command == 4:
                        change_mode(self.cipher)

                    if command == 5:
                        change_main_key(self, self.cipher)

                    if command == 6:
                        regenerate_sub_keys(self, self.cipher)

                    if command == 7:
                        print_config(self.cipher)

                    if command == 8:
                        view_pending_operations(self)

                    if command == 9:
                        self.close_application()
                        return None

                print("=" * 160)
                print(self.table)
                print(USER_INPUT_PROMPT)

    def close_application(self):
        """
        Terminates the application by setting a termination flag to
        end all current threads.

        @param self:
            A reference to the calling class object

        @return: None
        """
        print("[+] CLOSE APPLICATION: Now closing the application...")
        self.terminate = True
        print("[+] APPLICATION CLOSED: Application has been successfully terminated!")

    def save_cipher_state(self):
        """
        Saves the cipher's state (class attributes)
        by putting the cipher's configurations into
        a cache (list).

        @attention Use Case:
            This function is only used for avalanche analysis
            (SKAC) when the bits of the main key change.

        @return: None
        """
        print("=" * 160)
        print("[+] Saving cipher's state...")
        for attribute in vars(self.cipher).values():
            self.cipher_state.append(copy.deepcopy(attribute))
        print("[+] OPERATION SUCCESSFUL: The cipher's state has been saved!")
        print("=" * 160)

    def restore_cipher_state(self, cipher: object):
        """
        Restores the cipher's previous state after performing
        avalanche analysis (SKAC).

        @attention Use Case:
            This function is only used after avalanche analysis
            (SKAC) when the bits of the main key change.

        @param cipher:
            A CustomCipher object

        @return: None
        """
        print("=" * 160)
        print("[+] Restoring cipher's previous state...")
        cipher_attributes = list(vars(cipher).keys())

        # Iterate, unpack, and set each cipher attribute back to its previous state
        for attribute, value in zip(cipher_attributes, self.cipher_state):
            setattr(cipher, attribute, value)

        self.cipher_state.clear()
        print("[+] OPERATION SUCCESSFUL: The cipher's state has been restored!")
