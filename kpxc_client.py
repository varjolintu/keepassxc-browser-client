#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-
# Copyright (C) 2019 Sami Vänttinen <sami.vanttinen@protonmail.com>

import base64
import json
import os.path
import platform
import pysodium
import socket
import sys

SOCKET_NAME = 'kpxc_server'
BUFF_SIZE = 1024 * 1024

clientID = "kpxc_client"
publicKey = None
secretKey = None
serverPublicKey = None

if sys.version_info<(2,6,0) and sys.version_info >=(3,0,0):
    raise EnvironmentError("You need python 2.7 to run this script.")

if platform.system() == "Darwin" and os.path.exists(os.path.join(os.getenv('TMPDIR'), SOCKET_NAME)):
    server_address = os.path.join(os.getenv('TMPDIR'), SOCKET_NAME)
# For systemd - check if /tmp/kpxc_server exists - if not use systemd runtime dir
elif os.getenv('XDG_RUNTIME_DIR') is not None:
    server_address = os.path.join(os.getenv('XDG_RUNTIME_DIR'), SOCKET_NAME)
elif os.path.exists(os.path.join('/', 'tmp', SOCKET_NAME)):
    server_address = os.path.join('/', 'tmp', SOCKET_NAME)
else:
    raise OSError('Unknown path for keepassxc socket.')

sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
sock.settimeout(60)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, BUFF_SIZE)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, BUFF_SIZE)

def connectSocket():
    try:
        global sock, publicKey, secretKey
        sock.connect(server_address)
    except socket.error as msg:
        sock.close()
        sock = None

    if sock is not None:
        keypair = pysodium.crypto_box_keypair()
        publicKey = base64.b64encode(keypair[0])
        secretKey = base64.b64encode(keypair[1])

def disconnectSocket():
    sock.close()
    publicKey = None
    secretKey = None
    serverPublicKey = None

def changeClientID(id):
    clientID = id

def changePublicKeys():
    global publicKey, serverPublicKey, clientID
    nonce, incrementedNonce = __getNonces()
    msg = json.dumps({"action": "change-public-keys", "publicKey": publicKey, "nonce": nonce, "clientID": clientID})
    resp = __sendMessage(msg)
    response = json.loads(resp)

    if 'nonce' in response and response['nonce'] != incrementedNonce:
       return json.dumps({"error": "Nonce compare failed"})

    if 'publicKey' in response:
        serverPublicKey = response['publicKey']

    return response

def getDatabaseHash():
    global publicKey, secretKey, serverPublicKey, clientID
    nonce, incrementedNonce = __getNonces()
    encmsg = json.dumps({"action": "get-databasehash"})
    response = __sendAndWaitForResponse("get-databasehash", encmsg, nonce, serverPublicKey, secretKey, clientID)
    return __parseResponse(response, incrementedNonce)

def associate():
    global publicKey, secretKey, serverPublicKey, clientID
    nonce, incrementedNonce = __getNonces()
    idKey = base64.b64encode(pysodium.randombytes(pysodium.crypto_box_PUBLICKEYBYTES))
    encmsg = json.dumps({"action": "associate", "key": publicKey, "idKey": idKey})
    response = __sendAndWaitForResponse("associate", encmsg, nonce, serverPublicKey, secretKey, clientID)

    if response['nonce'] != incrementedNonce:
       return json.dumps({"error": "Nonce compare failed"})

    if 'message' in response:
        decrypted = __decrypt(response['message'], response['nonce'], serverPublicKey, secretKey)
        dec = json.loads(decrypted)
        dec['idKey'] = idKey # Wrap the idKey to the response
        return dec

    return response

def testAssociate(id, databasePublicKey):
    global publicKey, secretKey, serverPublicKey, clientID
    nonce, incrementedNonce = __getNonces()
    encmsg = json.dumps({"action": "test-associate", "id": id, "key": databasePublicKey})
    response = __sendAndWaitForResponse("test-associate", encmsg, nonce, serverPublicKey, secretKey, clientID)
    return __parseResponse(response, incrementedNonce)

def generatePassword():
    global publicKey, secretKey, serverPublicKey, clientID
    nonce, incrementedNonce = __getNonces()
    msg = json.dumps({"action": "generate-password", "nonce": nonce, "clientID": clientID})
    resp = __sendMessage(msg)
    response = json.loads(resp)
    return json.loads(__parseResponse(response, incrementedNonce))

def getLogins(url, id, key):
    global publicKey, secretKey, serverPublicKey, clientID
    nonce, incrementedNonce = __getNonces()
    encmsg = json.dumps({"action": "get-logins", "url": url, "submitUrl": url, "keys": [{"id": id, "key": key}]})
    response = __sendAndWaitForResponse("get-logins", encmsg, nonce, serverPublicKey, secretKey, clientID)
    return __parseResponse(response, incrementedNonce)

def setLogin(url, id, login, password, entryID):
    global publicKey, secretKey, serverPublicKey, clientID
    nonce, incrementedNonce = __getNonces()
    encmsg = json.dumps({"action": "set-login", "url": url, "id": id, "nonce": nonce, "login": login, "password": password, "uuid": entryID})
    response = __sendAndWaitForResponse("set-login", encmsg, nonce, serverPublicKey, secretKey, clientID)
    return __parseResponse(response, incrementedNonce)

def lockDatabase():
    global publicKey, secretKey, serverPublicKey, clientID
    nonce, incrementedNonce = __getNonces()
    encmsg = json.dumps({"action": "lock-database"})
    response = __sendAndWaitForResponse("lock-database", encmsg, nonce, serverPublicKey, secretKey, clientID)
    return __parseResponse(response, incrementedNonce)

def __encrypt(msg, nonce, serverKey, secretKey):
    enc = pysodium.crypto_box(msg, base64.b64decode(nonce), base64.b64decode(serverKey), base64.b64decode(secretKey))
    return base64.b64encode(enc)

def __decrypt(msg, nonce, serverKey, secretKey):
    dec = pysodium.crypto_box_open(base64.b64decode(msg), base64.b64decode(nonce), base64.b64decode(serverKey), base64.b64decode(secretKey))
    return dec

def __getNonces():
    nonce = __getNonce()
    return nonce, __getIncrementedNonce(nonce)

def __getNonce():
    return base64.b64encode(pysodium.randombytes(pysodium.crypto_box_NONCEBYTES))

def __getIncrementedNonce(nonce):
    oldNonce = list(base64.b64decode(nonce));

    i = 0
    c = 1
    for x in oldNonce:
        c += ord(x)
        oldNonce[i] = chr(c)
        c >>= 8
        i += 1

    return base64.b64encode("".join(oldNonce))

def __sendAndWaitForResponse(action, encmsg, nonce, serverPublicKey, secretKey, clientID):
    message = __encrypt(encmsg, nonce, serverPublicKey, secretKey)
    msg = json.dumps({"action": action, "message": message, "nonce": nonce, "clientID": clientID})
    resp = __sendMessage(msg)
    return json.loads(resp)

def __parseResponse(response, incrementedNonce):
    if 'nonce' in response and response['nonce'] != incrementedNonce:
        return json.dumps({"error": "Nonce compare failed"})

    if 'message' in response:
        decrypted = __decrypt(response['message'], response['nonce'], serverPublicKey, secretKey)
        return decrypted

    return response

def __sendMessage(msg):
    try:
        sock.send(msg)
    except socket.error:
        return json.dumps({})

    try:
        resp, server = sock.recvfrom(BUFF_SIZE)
        return resp
    except socket.timeout:
        return json.dumps({})
