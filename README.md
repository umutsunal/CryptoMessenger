# CryptoMessenger

An implementation of a crypto messenger in Java programming language.

CryptoMessenger application implements socket programming with Server and Client programs. Multiple Client programs can connect to the Server, and communicate with each other via GUI.

The client program supports two encryption modes (CBC, OFB), two encryption algorithms (AES, DES) and PKCS5 Padding.

Firstly, server program must be started. Then, client programs can be started. After running the client program, it asks for a username. When the user is connected, to be able to send the message, the program first encrypts the message with Encrypt button, then sends the message after pressing the Send button to all the clients via server program.   

The port number for the server is 9999, but it can be modified.
