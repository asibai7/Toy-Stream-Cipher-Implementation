Solution in C to a programming assignment from my Cryptography class - Toy Stream Cipher Implementation
This exercise will put basic cryptographic tools and toy stream cipher that were discussed during the class into action. Specifically, consider the toy stream cipher built from a Pseudo Random Number Generator 
(PRNG) as described in “Basics.ppt”, Slide 11. In this exercise, we will utilize the deterministic PRNG function ChaCha20 from Libtomcrypt. Moreover, as alluded to in Slide 12, to avoid repeating keys and 
information leakage, a PRNG must have a “seed”.
Alice:
1. Alice reads the message from the “Message.txt” file. The message size must be equal or greater than 32 bytes. (Read the message as unsigned char so that you could use the functions provided in in-class
exercises.)
3. Alice reads the shared seed from the “SharedSeed.txt” file. The seed is 32 Bytes (Read the message as unsigned char so that you could use the functions provided in in-class exercises.)
4. Alice generates the secret key from the shared seed based on utilizing the PRNG function from LibTomCrypt. The key size must match the message length.
5. Alice writes the Hex format of the key in a file named “Key.txt”.
6. Alice XORs the message with the secret key to obtain the ciphertext: (Ciphertext = M essage L Key).
7. Alice writes the Hex format of the ciphertext in a file named “Ciphertext.txt”.
8. Finally, Alice sends the ciphertext to Bob via zeroMQ. (The ciphertext format is unsigned char. Do Not send Hex strings!)
9. Alice is anticipating an ”acknowledgment” from Bob using ZeroMQ. This ”acknowledgment” refers to the hash value of the original text. Alice has the ability to match the hash she receives with the hash of the
original message. (Use SHA256 as Hash function)
11. If the comparison is successful, Alice can be confident that Bob has received the accurate message. She then writes ”Acknowledgment Successful” in a file called ”Acknowledgment.txt.” Conversely, if the
comparison fails, she records ”Acknowledgment Failed.”

Bob:
1. Bob receives the ciphertext from Alice via ZeroMQ.
2. Bob reads the shared seed from the “SharedSeed.txt” file. The seed is 32 Bytes (Read the message as unsigned char so that you could use the functions provided in in-class exercises.)
3. Bob generates the secret key from the shared seed based on utilizing the PRNG function from LibTomCrypt. The key size must match the message length.
4. Bob XORs the received ciphertext with the secret key to obtain the plaintext: (plaintext = ciphertext L key).
5. Bob writes the decrypted plaintext in a file named “Plaintext.txt”.
6. Bob hashes the plaintext via SHA256 and writes the Hex format of the hash in a file named ”Hash.txt”.
7. Finally, Bob sends the hash over ZeroMQ to the Alice as an Acknowledgment. (Do Not send Hex format! Use unsigned char to send the data.)
