# HAS YOUR PASSWORD EVER BEEN HACKED ?!?!?!?

import requests
import hashlib
import sys
from pathlib import Path

class PasswordChecker():
    def __init__(self, args, type):
        """
        :param args: passwords to check or a path to a txt file with the passwords.
        :param type: either 'PATH' or 'LIST' --> the type of args.
        """
        self.args = args
        self.type = type
    def request_api_data(self):
        """
        this function sends a request to the password api.
        this api gets the first 5 chars of the hashed version of the password.
        the api returns all the leaked passwords hashes that start with those first 5 chars.
        :param query_char: string, the hashed version of the password to check.
        :return: the response from the api
        """
        query_char = self.first5_char
        url = 'https://api.pwnedpasswords.com/range/' + query_char
        res = requests.get(url)
        if res.status_code != 200:
            raise RuntimeError(f'error fetching: {res.status_code}, check the api and try again')
        return res

    def get_password_leaks_count(self):
        """
        this function checks how many times the password's hash is found in the response.
        :param hashes: the response from the API, contains the leaked hashes
        :param hash_to_check: the tail of the password hash to check (all but first 5 chars)
        :return: the password's hash leaks count
        """
        hashes = self.response
        hash_to_check = self.tail
        hashes = (line.split(':') for line in hashes.text.splitlines())
        for h, count in hashes:
            if h == hash_to_check:
                return count
        return 0

    def powned_api_check(self, password):
        """
        this function check if password exists in the API response
        :param password: string, the password to check
        :return: count of the password's leaks
        """
        #
        sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        self.first5_char, self.tail = sha1password[:5], sha1password[5:]
        self.response = self.request_api_data()
        return self.get_password_leaks_count()

    def main_check_passwords(self):
        """
        the main function to check if the password has been leaked.
        :param args: strings, the password to check.
        :return: None. prints the leaks count.
        """
        if self.type == 'PATH':
            txt_file = Path(self.args).read_text()
            passwords = (line for line in txt_file.splitlines())
        else:
            passwords = self.args
        for password in passwords:
            count = self.powned_api_check(password)
            if count:
                print(f'password {password} has been hacked {count} times !!! you should consider changing it...')
            else:
                print(f'password {password} has not been hacked !! carry on with it.')
        return 'done!'

if __name__ == '__main__':
    c = PasswordChecker('passwords.txt', 'PATH')
    c.main_check_passwords()
