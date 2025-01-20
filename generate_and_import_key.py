import boto3
import subprocess
import os

def run_command(command):
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"Error running command: {command}")
        print(result.stderr)
        exit(1)
    return result.stdout

def main(aws_key_id):
    kms_client = boto3.client('kms')

    # Get parameters for import
    response = kms_client.get_parameters_for_import(
        KeyId=aws_key_id,
        WrappingAlgorithm='RSA_AES_KEY_WRAP_SHA_256',
        WrappingKeySpec='RSA_4096'
    )

    wrapping_key = response['PublicKey']
    import_token = response['ImportToken']

    private_key_file = 'private.pem'
    public_key_file = 'public.pem'

    dkim_extension = 'ses.dkim'
    private_key_ses_dkim_file = f"{private_key_file}.{dkim_extension}"
    public_key_ses_dkim_file = f"{public_key_file}.{dkim_extension}"

    private_key_der_file = 'private.der'
    private_key_pkcs8_file = 'private.pkcs8'

    # Generate a private key
    run_command(f"openssl genrsa -f4 -out {private_key_file} 2048")

    # Generate the public key
    run_command(f"openssl rsa -in {private_key_file} -pubout -out {public_key_file}")

    # Convert to the AWS SES DKIM versions
    run_command(f"grep -v 'PRIVATE KEY' {private_key_file} | tr -d '\\n' > {private_key_ses_dkim_file}")
    run_command(f"grep -v 'PUBLIC KEY' {public_key_file} | tr -d '\\n' > {public_key_ses_dkim_file}")

    # Convert to the AWS KMS DER format
    run_command(f"openssl rsa -in {private_key_file} -outform DER -out {private_key_der_file}")

    # Convert to the PKCS8 format
    run_command(f"openssl pkcs8 -topk8 -inform DER -outform DER -in {private_key_der_file} -out {private_key_pkcs8_file} -nocrypt")

    # Generate a 32-byte AES symmetric encryption key
    run_command("openssl rand -out aes-key.bin 32")

    # Encrypt the private key using the AES key
    run_command(f"openssl enc -id-aes256-wrap-pad -K \"$(xxd -p < aes-key.bin | tr -d '\\n')\" -iv A65959A6 -in {private_key_pkcs8_file} -out key-material-wrapped.bin")

    # Save the wrapping key to a file
    with open('WrappingPublicKey.bin', 'wb') as f:
        f.write(wrapping_key)

    # Encrypt the AES key using the KMS WrappingPublicKey
    run_command("openssl pkeyutl -encrypt -in aes-key.bin -out aes-key-wrapped.bin -inkey WrappingPublicKey.bin -keyform DER -pubin -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 -pkeyopt rsa_mgf1_md:sha256")

    # Combine the encrypted AES key and the encrypted private key
    run_command("cat aes-key-wrapped.bin key-material-wrapped.bin > EncryptedKeyMaterial.bin")

    # Import the key material
    kms_client.import_key_material(
        KeyId=aws_key_id,
        EncryptedKeyMaterial=open('EncryptedKeyMaterial.bin', 'rb').read(),
        ImportToken=import_token,
        ExpirationModel='KEY_MATERIAL_DOES_NOT_EXPIRE'
    )

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python generate_and_import.py <aws-kms-key-id>")
        sys.exit(1)
    main(sys.argv[1])