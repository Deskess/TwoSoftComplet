import hashlib
import hmac
import secrets

from src.DataAccess import Access


class DatabaseSystem:
    def __init__(self, data_path="assets_json\\data.json"):
        self._access = Access(data_path)
        self._authenticated = False
        self._authenticated_user = None
        self._authenticated_password_hash = None

    @staticmethod
    def hash_password(password):
        return hashlib.sha256(password.encode("utf-8")).hexdigest()

    def login(self, username, password):
        password_hash = self.hash_password(password)
        self._authenticated = False
        self._authenticated_user = None
        self._authenticated_password_hash = None

        account = self._access.get_account(username)
        if account is not None and hmac.compare_digest(
            account.get("PasswordHash", ""), password_hash
        ):
            self._authenticated = True
            self._authenticated_user = username
            self._authenticated_password_hash = password_hash
        else:
            for entry in self._access._read_data():
                if entry.get("User") == username and hmac.compare_digest(
                    entry.get("PasswordHash", ""), password_hash
                ):
                    self._authenticated = True
                    self._authenticated_user = username
                    self._authenticated_password_hash = password_hash
                    break
        return self._authenticated

    def generate_activation_key(self):
        used_key_hashes = self._access.get_used_activation_key_hashes()
        while True:
            key = str(
                secrets.randbelow(9_000_000_000_000_000)
                + 1_000_000_000_000_000
            )
            key_hash = self.hash_password(key)
            if key_hash not in used_key_hashes:
                return key

    def activate_account(self, username, password, activation_key, issued_key):
        username = username.strip()
        if not username:
            raise ValueError("Username cannot be empty.")
        if not password:
            raise ValueError("Password cannot be empty.")
        if not hmac.compare_digest(activation_key, issued_key):
            raise ValueError("The activation key is invalid.")
        if self._access.is_username_taken(username):
            raise ValueError("That username is already in use.")
        self._access.add_account(
            username,
            self.hash_password(password),
            self.hash_password(activation_key),
        )

    def logout(self):
        self._authenticated = False
        self._authenticated_user = None
        self._authenticated_password_hash = None

    def _require_login(self):
        if not self._authenticated:
            raise PermissionError("Login required to access the database.")

    def print_content(self):
        self._require_login()
        self._access.print_content(self._authenticated_user)

    def add(self, _user, age, category, price, article):
        self._require_login()
        self._access.add(
            self._authenticated_user,
            age,
            category,
            price,
            article,
            self._authenticated_password_hash,
        )

    def get_data(self, user):
        self._require_login()
        return self._access.get_data(user, self._authenticated_user)

    def get_by_hash_table(self, hash_table_number):
        self._require_login()
        return self._access.get_by_hash_table(
            hash_table_number, self._authenticated_user
        )
