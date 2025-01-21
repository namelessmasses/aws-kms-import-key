import argparse
import os

parser = argparse.ArgumentParser(description='Get DKIM keys from SES')
parser.add_argument('key_id', help='The AWS KMS key ID')
args = parser.parse_args()

with open(f'{args.key_id}.private.pem', 'r') as f:
    key = [s.strip() for s in f.readlines()]

print(os.linesep.join(key))
print()

key_flat = ''.join(key[1:-1])
print('Flattened private key:')
print(key_flat)
print()

# split private_key into chunks of n characters
n = 256
key_chunks = [key_flat[i:i+n] for i in range(0, len(key_flat), n)]

# print the chunks as double quoted strings separated by spaces
print('Formatted for DKIM:')
print(' '.join([f'"{chunk}"' for chunk in key_chunks]))
print()

with open(f'{args.key_id}.public.pem', 'r') as f:
    key = [s.strip() for s in f.readlines()]
    
print(os.linesep.join(key))
print()

key_flat = ''.join(key[1:-1])
print('Flattened public key:')
print(key_flat)
print()

# split public_key into chunks of n characters
# n = 512
key_chunks = [key_flat[i:i+n] for i in range(0, len(key_flat), n)]

# print the chunks as double quoted strings separated by spaces
print('Formatted for DKIM:')
print(' '.join([f'"{chunk}"' for chunk in key_chunks]))
print()

    