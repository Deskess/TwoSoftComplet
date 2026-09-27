import hashlib
import json
from pathlib import Path


class Access:
    def __init__(self, file_path="\\assets_json\\data.json"):
        self.file_path = Path(file_path)
        self.accounts_path = self.file_path.with_name("accounts.json")
        if not self.file_path.exists():
            self._write_data([])

    def _read_data(self):
        with self.file_path.open("r", encoding="utf-8") as file:
            return json.load(file)

    def _write_data(self, data):
        with self.file_path.open("w", encoding="utf-8") as file:
            json.dump(data, file, indent=4)

    def _read_accounts(self):
        if not self.accounts_path.exists():
            return {"Accounts": [], "UsedActivationKeys": []}
        with self.accounts_path.open("r", encoding="utf-8") as file:
            accounts_data = json.load(file)
        if not isinstance(accounts_data, dict) or not isinstance(
            accounts_data.get("Accounts"), list
        ) or not isinstance(accounts_data.get("UsedActivationKeys"), list):
            raise ValueError("The accounts file has an invalid format.")
        return accounts_data

    def get_account(self, username):
        for account in self._read_accounts()["Accounts"]:
            if account.get("User") == username:
                return account
        return None

    def is_username_taken(self, username):
        if self.get_account(username) is not None:
            return True
        return any(
            entry.get("User") == username for entry in self._read_data()
        )

    def get_used_activation_key_hashes(self):
        return set(self._read_accounts()["UsedActivationKeys"])

    def add_account(self, username, password_hash, activation_key_hash):
        accounts_data = self._read_accounts()
        if self.is_username_taken(username):
            raise ValueError("That username is already in use.")
        if activation_key_hash in accounts_data["UsedActivationKeys"]:
            raise ValueError("That activation key has already been used.")
        accounts_data["Accounts"].append(
            {"User": username, "PasswordHash": password_hash}
        )
        accounts_data["UsedActivationKeys"].append(activation_key_hash)
        with self.accounts_path.open("w", encoding="utf-8") as file:
            json.dump(accounts_data, file, indent=4)

    @staticmethod
    def _create_hash_table_number(user, age):
        hash_input = f"{user}:{age}".encode("utf-8")
        digest = hashlib.sha256(hash_input).hexdigest()
        return 100_000 + (int(digest, 16) % 900_000)

    def add(self, user, age, category, price, article, password_hash):
        data = self._read_data()
        data.append(
            {
                "User": user,
                "Age": age,
                "Category": category,
                "Price": price,
                "Article": article,
                "HashTable": self._create_hash_table_number(user, age),
                "PasswordHash": password_hash,
            }
        )
        self._write_data(data)

    def print_content(self, owner):
        data = self._read_data()
        data = [entry for entry in data if entry.get("User") == owner]
        print(json.dumps(data, indent=4))

    def get_data(self, user, owner):
        for entry in self._read_data():
            if entry.get("User") == user and entry.get("User") == owner:
                return entry
        return None

    def get_by_hash_table(self, hash_table_number, owner):
        for entry in self._read_data():
            if entry.get("HashTable") == hash_table_number and entry.get(
                "User"
            ) == owner:
                return entry
        return None
