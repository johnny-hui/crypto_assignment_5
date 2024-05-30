import select
import sys
from models.CustomCipher import CustomCipher
from utility.constants import USER_INPUT_PROMPT, USER_MENU_TITLE, USER_MENU_COLUMNS, \
    MIN_MENU_ITEM_VALUE, MAX_MENU_ITEM_VALUE, USER_MENU_OPTIONS_LIST
from utility.init import print_config
from utility.utilities import get_user_menu_option, make_table, change_mode, change_main_key, regenerate_sub_keys, \
    encrypt, view_pending_operations, decrypt


class UserViewModel:
    """A ViewModel class for an interactable user menu.

    Attributes:
        table - A table containing several user menu options
        cipher - A CustomCipher object
        terminate - A boolean for the termination of the application
        pending_operations - A dictionary (cache) that stores pending operations for the current state
    """
    def __init__(self, *args):
        self.table = make_table(USER_MENU_TITLE, USER_MENU_COLUMNS, USER_MENU_OPTIONS_LIST)
        self.cipher = CustomCipher(key=args[0], mode=args[1], subkey_flag=args[2])
        self.terminate = False
        self.pending_operations = {}  # Format => {Encrypted_Format: (mode, cipher_text/path_to_file, IV)}

    def start(self):
        """
        Starts the application.
        @return: None
        """
        self.__menu()

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
                        change_mode(self.cipher)

                    if command == 4:
                        change_main_key(self, self.cipher)

                    if command == 5:
                        regenerate_sub_keys(self, self.cipher)

                    if command == 6:
                        print_config(self.cipher)

                    if command == 7:
                        view_pending_operations(self)

                    if command == 8:
                        self.close_application()
                        return None

                print("=" * 160)
                print(self.table)
                print(USER_INPUT_PROMPT)
