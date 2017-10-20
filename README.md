# MACAttack
Message Authentication Code Extension Attack

This attack is designed to take advantage of a limitation in the SHA-1 algorithm when used for message integrity.

For example, if MAC is created by taking the SHA-1 hash of a secret key concatenated with the message, then you can append to the new message and generate a new MAC using this modified sha-1 algorithm. This is possible because SHA-1 hashes block by block.

Limitations:
- The message must be a multiple of 8 bits (easy with text files)
- The original mac must be generated from SHA-1 with the message appended to the key (key first). H(K || m)
- The key size must be known
- The new message will have padding inside (0x1000...), although this is usually not rendered by text viewers.

### Example
Alice sends Bob "You are the best" with a MAC generated from a secret key and message.
Mallory can modify the message to read "You are the best at being a terrible person" and generate a new mac without knowing the secret key.
When Bob receives the message, he will verify the integrity by generating the mac with the spoofed message and the secret key, and it will be the same as the MAC Mallory sent.

# Usage
### macExtensionMessage(original_message, key_size, new_message);
This generates the spoofed message to send by appending the proper padding and new message.

### macExtensionMac(original_mac, key_size, new_message, spoofed_message);
This generates the spoofed MAC by using a modified SHA-1 that is initialized with the original MAC.
