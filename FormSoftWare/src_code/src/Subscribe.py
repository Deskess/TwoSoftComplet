from getpass import getpass

from src.Login import DatabaseSystem


def create_account(database=None):
    database = database or DatabaseSystem()
    issued_key = database.generate_activation_key()
    print(f"Your one-time activation key is: {issued_key}")
    activation_key = input("Enter the activation key to continue: ").strip()
    if activation_key != issued_key:
        print("Activation failed: the key does not match.")
        return False

    username = input("Choose a username: ").strip()
    password = getpass("Set a password: ")
    password_confirmation = getpass("Confirm the password: ")
    if password != password_confirmation:
        print("Account creation failed: passwords do not match.")
        return False

    try:
        database.activate_account(
            username, password, activation_key, issued_key
        )
    except ValueError as error:
        print(f"Account creation failed: {error}")
        return False

    print("Account activated successfully. You can now log in.")
    return True


if __name__ == "__main__":
    create_account()