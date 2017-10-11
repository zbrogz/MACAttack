# MACAttack
Message Authentication Code Extension Attack

This attack is designed to take advantage of a limitation in the SHA-1 algorithm when used for message integrity.

For example, if MAC is created by taking the SHA-1 hash of a secret key concatenated with the message, then you can append to the new message and generate a new MAC using this modified sha-1 algorithm. This is possible because SHA-1 hashes block by block.

Limitations:
- The message must be a multiple of 8 bits (easy with text files)
- The original mac must be generated from SHA-1 with the message appended to the key (key first).

# Usage
### macExtensionMessage(original_message, key_size, new_message);
This generates the spoofed message to send by appending the proper padding and new message.

### macExtensionMac(original_mac, key_size, new_message, spoofed_message);
This generates the spoofed MAC by using a modified SHA-1 that is initialized with the original MAC.
