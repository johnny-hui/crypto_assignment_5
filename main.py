from models.UserMenu import UserMenu
from utility.init import parse_arguments

if __name__ == '__main__':
    mode, subkey_flag, key = parse_arguments()
    menu = UserMenu(key, mode, subkey_flag)
    menu.start()

