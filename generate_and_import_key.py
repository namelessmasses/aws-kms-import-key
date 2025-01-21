import boto3
import argparse
from cryptography.hazmat.primitives import serialization, keywrap, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import os

def parse_arguments():
    parser = argparse.ArgumentParser(description='Generate and import key material into AWS KMS.')
    parser.add_argument('--key-id', nargs='?', type=str, required=True, help='The AWS KMS key ID')
    parser.add_argument('--region', nargs='?', type=str, default='us-west-2', help='The AWS region (default: us-west-2)')
    return parser.parse_args()

def main(args):
    kms_client = boto3.client('kms', region_name=args.region)

    # Get parameters for import
    response = kms_client.get_parameters_for_import(
        KeyId=args.key_id,
        WrappingAlgorithm='RSA_AES_KEY_WRAP_SHA_256',
        WrappingKeySpec='RSA_4096'
    )

    aws_public_key = response['PublicKey']
    aws_public_key = serialization.load_der_public_key(aws_public_key)

    import_token = response['ImportToken']

    # Generate a private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048)
    
    key_to_wrap = private_key.private_bytes(
        encoding=serialization.Encoding.DER, 
        format=serialization.PrivateFormat.PKCS8, 
        encryption_algorithm=serialization.NoEncryption())

    aes_key = os.urandom(32)
    
    # Wrap the private key with the AES key using AES key wrap with padding
    key_material_wrapped = keywrap.aes_key_wrap_with_padding(wrapping_key=aes_key, key_to_wrap=key_to_wrap)
    
    # Encrypt the AES key with the AWS public key
    aes_key_wrapped = aws_public_key.encrypt(
        aes_key,
        padding=padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    # Concatenate the wrapped AES key and the wrapped key material
    encrypted_key_material = aes_key_wrapped + key_material_wrapped

    # Import the key material
    kms_client.import_key_material(
        KeyId=args.key_id,
        EncryptedKeyMaterial=encrypted_key_material,
        ImportToken=import_token,
        ExpirationModel='KEY_MATERIAL_DOES_NOT_EXPIRE'
    )
    
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Output the private key
    with open(f'{args.key_id}.private.pem', 'wb') as f:
        f.write(private_pem)

    # Output the public key        
    with open(f'{args.key_id}.public.pem', 'wb') as f:
        f.write(public_pem)

if __name__ == "__main__":
    args = parse_arguments()
    main(args)