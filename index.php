<?php

error_reporting(E_ALL);
ini_set('display_errors', 'On');
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/functions.php';

try {
    //Initial ein paar User Keys anlegen
    //createInitialKeys('test','test');
    //createInitialKeys('test2','test');

    //Sende Message zum User test2
    sendSealedMessageTo(['test2'], 'test subject', 'streng geheime nachricht<br/>');
    //Lese Message als User test2 mit seinem Passwort
    echo getSealedMessageContent('test2', 'test', 'test subject');
    //Passwort vom test2 ändern
    changeKeyPassword('test2', 'test', 'test2');
    //Prüfen ob man die Message lesen kann mit neuen Passwort
    echo getSealedMessageContent('test2', 'test2', 'test subject');
    //Passwort resetten
    changeKeyPassword('test2', 'test2', 'test');
} catch (Exception $e) {
    echo "Konnte key nicht erstellen weil: " . $e->getMessage();
}

