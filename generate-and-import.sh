[ -z "$1" ] && echo "Usage: $0 <aws-kms-key-id>" && exit 1

PRIVATE_KEY_FILE=private.pem
PUBLIC_KEY_FILE=public.pem

DKIM_EXTENSION=ses.dkim
PRIVATE_KEY_SES_DKIM_FILE="$PRIVATE_KEY_FILE.$DKIM_EXTENSION"
PUBLIC_KEY_SES_DKIM_FILE="$PUBLIC_KEY_FILE.$DKIM_EXTENSION"

PRIVATE_KEY_DER_FILE=private.der

PRIVATE_KEY_PKCS8_FILE=private.pkcs8

# Generate an private key
#openssl genrsa -f4 -out private.pem 2048
openssl ecparam -name secp521r1 -genkey -noout -out $PRIVATE_KEY_FILE

# Generate the public key
#openssl rsa -in private.pem -pubout -out public.pem
openssl ec -in $PRIVATE_KEY_FILE -pubout -out $PUBLIC_KEY_FILE

# Convert to the AWS SES DKIM versions
# Use these when entering DKIM keys in the AWS SES console
grep -v 'PRIVATE KEY' $PRIVATE_KEY_FILE | tr -d '\n' > $PRIVATE_KEY_SES_DKIM_FILE
grep -v 'PUBLIC KEY' $PUBLIC_KEY_FILE | tr -d '\n' > $PUBLIC_KEY_SES_DKIM_FILE

# Convert to the AWS KMS DER format
#openssl rsa -in private.pem -outform DER -out private.der
openssl ec -in $PRIVATE_KEY_FILE -outform DER -out $PRIVATE_KEY_DER_FILE

# Convert to the PKCS8 format
openssl pkcs8 -topk8 -inform DER -outform DER -in $PRIVATE_KEY_DER_FILE -out $PRIVATE_KEY_PKCS8_FILE -nocrypt

# Wrap private.pkcs8 using RSA_AES_KEY_WRAP_SHA_256 wrapping algorithm
# https://docs.aws.amazon.com/kms/latest/developerguide/importing-keys-encrypt-key-material.html

# Generate a 32-byte AES symmetric encryption key
openssl rand -out aes-key.bin 32

# Encrypt the private key using the AES key
# Encrypt your key material with the AES symmetric encryption key
openssl enc -id-aes256-wrap-pad \
        -K "$(xxd -p < aes-key.bin | tr -d '\n')" \
        -iv A65959A6 \
        -in $PRIVATE_KEY_PKCS8_FILE \
        -out key-material-wrapped.bin


# Encrypt the AES key using the KMS WrappingPublicKey
# Encrypt your AES symmetric encryption key with the downloaded public key
openssl pkeyutl \
    -encrypt \
    -in aes-key.bin \
    -out aes-key-wrapped.bin \
    -inkey WrappingPublicKey.bin \
    -keyform DER \
    -pubin \
    -pkeyopt rsa_padding_mode:oaep \
    -pkeyopt rsa_oaep_md:sha256 \
    -pkeyopt rsa_mgf1_md:sha256

# Combine the encrypted AES key and the encrypted private key
cat aes-key-wrapped.bin key-material-wrapped.bin > EncryptedKeyMaterial.bin

# Import the key material
#aws kms import-key-material --key-id $1 --encrypted-key-material fileb://EncryptedKeyMaterial.bin --import-token fileb://ImportToken.bin 