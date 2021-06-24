<?php

error_reporting(E_ALL);
ini_set('display_errors', 'On');
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/functions.php';

try {
    //createInitialKeys('test','test');
    //createInitialKeys('test2','test');

    sendSealedMessageTo(['test2'], 'test suject', 'streng geheime nachricht<br/>');
    //read message
    echo getSealedMessageContent('test2', 'test', 'test suject');
    //change password
    changeKeyPassword('test2', 'test', 'test2');
    //check password change worked
    echo getSealedMessageContent('test2', 'test2', 'test suject');
    //set password back to original
    changeKeyPassword('test2', 'test2', 'test');
} catch (Exception $e) {
    echo "Konnte key nicht erstellen weil: " . $e->getMessage();
}

