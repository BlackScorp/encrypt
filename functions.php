<?php

function createInitialKeys(string $username, string $password): void
{
    $keyFile = KEY_DIR . '/' . $username;
    if (is_file($keyFile)) {
        throw new Exception(sprintf('Keyfile already exists for user %s', $username));
    }
    $key = openssl_pkey_new(OPENSSL_CONFIG);

    if (false === $key) {
        throw new Exception(openssl_error_string());
    }
    $exported = openssl_pkey_export($key, $privateKeyString, $password);
    if (false === $exported) {
        throw new Exception(openssl_error_string());
    }
    $publicKeyDetails = openssl_pkey_get_details($key);
    if (false === $publicKeyDetails) {
        throw new Exception('Failed to get private key details');
    }
    $publicKeySting = $publicKeyDetails['key'];


    $created = file_put_contents($keyFile . '.pub', $publicKeySting);
    if (false === $created) {
        throw new Exception(sprintf('Failed to create public key file "%s"', $keyFile . '.pub'));
    }
    $created = file_put_contents($keyFile, $privateKeyString);
    if (false === $created) {
        throw new Exception(sprintf('Failed to create private key file "%s"', $keyFile));
    }
}

function sendSealedMessageTo(array $recipients, $subject, $message): bool
{
    if (0 === count($recipients)) {
        throw new Exception('No recipients');
    }
    $publicKeys = [];
    $encryptedKeys = [];

    foreach ($recipients as $recipient) {
        $keyFileName = KEY_DIR . '/' . $recipient . '.pub';
        if (!is_file($keyFileName)) {
            throw new Exception(sprintf('Public key for %s not found', $recipient));
        }
        $publicKeyString = file_get_contents($keyFileName);
        if (false === $publicKeyString) {
            throw new Exception(sprintf('Cannot read public key %s', $publicKeyString));
        }
        $publicKey = openssl_get_publickey($publicKeyString);
        if (false === $publicKey) {
            throw new Exception(sprintf('Invalid public key %s: %s', $publicKeyString, openssl_error_string()));
        }
        $publicKeys[] = $publicKey;
    }
    $iv = openssl_random_pseudo_bytes(RANDOM_BYTE_LENGTH);
    if (false === $iv) {
        throw new Exception('Failed to generate random pseudo bytes: ' . openssl_error_string());
    }
    $cipherMethods = openssl_get_cipher_methods();
    shuffle($cipherMethods);
    $randomCipher = current($cipherMethods);

    $sealed = openssl_seal($message, $sealedMessage, $encryptedKeys, $publicKeys, $randomCipher, $iv);

    if (false === $sealed) {
        throw new Exception(sprintf('Failed to seal the message %s' . openssl_error_string()));
    }
    $messageFileName = convertSubjectToFileName($subject);

    foreach ($encryptedKeys as $recipientNumber => $encryptedKey) {
        $content = base64_encode($sealedMessage) . MESSAGE_PARTS_SEPARATOR;
        $content .= base64_encode($encryptedKey) . MESSAGE_PARTS_SEPARATOR;
        $content .= base64_encode($iv) . MESSAGE_PARTS_SEPARATOR;
        $content .= $randomCipher;

        $recipient = $recipients[$recipientNumber];

        $recipientMessageDirectory = MESSAGE_DIR . '/' . $recipient;
        if (!is_dir($recipientMessageDirectory)) {
            $folderCreated = mkdir($recipientMessageDirectory);
            if (false === $folderCreated) {
                throw new Exception(sprintf('Failed to create folder %s', $recipientMessageDirectory));
            }
        }

        $messageSaved = file_put_contents($recipientMessageDirectory . '/' . $messageFileName, $content);
        if (false === $messageSaved) {
            throw new Exception(
                sprintf('Failed to save message into %s', $recipientMessageDirectory . '/' . $messageFileName)
            );
        }
    }
    return true;
}

function getSealedMessageContent(string $username, string $password, string $subject): string
{
    $messageFile = MESSAGE_DIR . '/' . $username . '/' . convertSubjectToFileName($subject);

    if (!is_file($messageFile)) {
        throw new Exception(sprintf('Message file %s not exists', $messageFile));
    }

    $privateKey = getPrivateKey($username, $password);

    $content = file_get_contents($messageFile);
    if (false === $content) {
        throw new Exception(sprintf('Failed to read file %s', $messageFile));
    }
    $messageParts = explode(MESSAGE_PARTS_SEPARATOR, $content);

    if (4 !== count($messageParts)) {
        throw new Exception(sprintf('Message %s is invalid and has not enough parts', $messageFile));
    }
    [$sealedMessage, $messageKey, $iv, $randomCipher] = $messageParts;

    $sealedMessage = base64_decode($sealedMessage);
    if (false === $sealedMessage) {
        throw new Exception(sprintf('Failed to encode sealed message in %s', $messageFile));
    }
    $messageKey = base64_decode($messageKey);
    if (false === $messageKey) {
        throw new Exception(sprintf('Failed to encode message key in %s', $messageFile));
    }
    $iv = base64_decode($iv);
    if (false === $iv) {
        throw new Exception(sprintf('Failed to encode random bytes in %s', $messageFile));
    }

    $randomCipher = trim($randomCipher);

    $messageText = '';

    if (!openssl_open($sealedMessage, $messageText, $messageKey, $privateKey, $randomCipher, $iv)) {
        throw new Exception(sprintf('Failed to decrypt message %s', openssl_error_string()));
    }
    return $messageText;
}

function changeKeyPassword(string $username, string $oldPassword, string $newPassword): void
{
    $privateKeyFile = KEY_DIR . '/' . $username;

    $privateKey = getPrivateKey($username, $oldPassword);

    $privateKeyString = '';
    $exported = openssl_pkey_export($privateKey, $privateKeyString, $newPassword);
    if (false === $exported) {
        throw new Exception(sprintf('Failed to export private key %s', openssl_error_string()));
    }
    $saved = file_put_contents($privateKeyFile, $privateKeyString);
    if (false === $saved) {
        throw  new Exception(sprintf('Failed to save private key file %s', $privateKeyFile));
    }
}

function getPrivateKey(string $username, string $password)
{
    $privateKey = KEY_DIR . '/' . $username;
    if (!is_file($privateKey)) {
        throw new Exception(sprintf('Private Key %s not found for user', $privateKey));
    }

    $privateKeyFileContent = file_get_contents($privateKey);
    if (false === $privateKeyFileContent) {
        throw new Exception(sprintf('Failed to read file %s', $privateKeyFileContent));
    }
    $privateKey = openssl_get_privatekey($privateKeyFileContent, $password);
    if (!$privateKey) {
        throw new Exception(sprintf('Failed to get private key %s', openssl_error_string()));
    }
    return $privateKey;
}

function convertSubjectToFileName(string $subject): string
{
    $subject = trim($subject);
    $messageFileName = preg_replace('/[^A-z0-9-]/m', '_', $subject);
    $messageFileName = preg_replace('/_{2,}/m', '_', $messageFileName);
    return $messageFileName . '.message';
}