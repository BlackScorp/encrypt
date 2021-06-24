<?php

const OPENSSL_CONFIG = [
    'config' => '/etc/ssl/openssl.cnf'
];

const STORAGE_DIR = __DIR__ . '/storage';
const KEY_DIR = STORAGE_DIR . '/keys';
const MESSAGE_DIR = STORAGE_DIR . '/messages';
const MESSAGE_PARTS_SEPARATOR = "\n---PART---\n";
const RANDOM_BYTE_LENGTH = 32;