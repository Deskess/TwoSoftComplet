from getpass import getpass

from src.Login import DatabaseSystem
from src.Subscribe import create_account


def print_menu():
    print("\nDatabase menu")
    print("1. Display my records")
    print("2. Add a record")
    print("3. Search my records by user")
    print("4. Search my records by hash-table number")
    print("5. Exit")


def add_record(database):
    age = int(input("Age: "))
    category = input("Category: ").strip()
    price = float(input("Price: "))
    article = input("Article: ").strip()
    database.add("", age, category, price, article)
    print("Record added.")


def search_by_user(database):
    user = input("User to search for: ").strip()
    record = database.get_data(user)
    print(record if record is not None else "No record found.")


def search_by_hash_table(database):
    hash_table = int(input("Hash-table number: "))
    record = database.get_by_hash_table(hash_table)
    print(record if record is not None else "No record found.")


def run_menu():
    database = DatabaseSystem()
    while True:
        print("\nAccount menu")
        print("1. Log in")
        print("2. Activate a new account")
        print("3. Exit")
        account_choice = input("Choose an option: ").strip()

        if account_choice == "2":
            create_account(database)
            continue
        if account_choice == "3":
            print("Goodbye.")
            return
        if account_choice != "1":
            print("Invalid option. Choose a number from 1 to 3.")
            continue

        username = input("Username: ").strip()
        password = getpass("Password: ")
        if not database.login(username, password):
            print("Invalid username or password.")
            continue

        print("Login successful.")
        while True:
            print_menu()
            choice = input("Choose an option: ").strip()
            try:
                if choice == "1":
                    database.print_content()
                elif choice == "2":
                    add_record(database)
                elif choice == "3":
                    search_by_user(database)
                elif choice == "4":
                    search_by_hash_table(database)
                elif choice == "5":
                    database.logout()
                    print("Logged out.")
                    break
                else:
                    print("Invalid option. Choose a number from 1 to 5.")
            except ValueError:
                print("Invalid number. Please try again.")


if __name__ == "__main__":
    run_menu()
