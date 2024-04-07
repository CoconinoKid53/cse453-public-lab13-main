
##############################################################################
# COMPONENT:
#    CIPHER01
# Author:
#    Br. Helfrich, Kyle Mueller, <your name here if you made a change>
# Summary:
#    Implement your cipher here. You can view 'example.py' to see the
#    completed Caesar Cipher example.
##############################################################################


##############################################################################
# CIPHER
##############################################################################
class KeycodeCipher:
    def __init__(self):
        self.keycode = self.generate_keycode_mapping()

    def generate_keycode_mapping(self):
        keycode = {}
        for i in range(128):
            keycode[chr(i)] = i
        return keycode

    def encrypt(self, plaintext, keyword):
        keyword_alphabet = self.create_alphabet_keyword(keyword)
        ciphertext = ''
        for char in plaintext:
            if char in keyword_alphabet:
                index = (self.keycode[char] + len(keyword_alphabet)) % 128
                ciphertext += chr(index)
            else:
                ciphertext += char
        return ciphertext

    def decrypt(self, ciphertext, keyword):
        keyword_alphabet = self.create_alphabet_keyword(keyword)
        plaintext = ''
        for char in ciphertext:
            if char in keyword_alphabet:
                index = (self.keycode[char] - len(keyword_alphabet)) % 128
                plaintext += chr(index)
            else:
                plaintext += char
        return plaintext

    def create_alphabet_keyword(self, keyword):
        alphabet_list = list("".join([chr(i) for i in range(128)]))
        keyword = keyword.upper()
        result = ''
        for char in keyword:
            if char in alphabet_list:
                result += char
        return result

    def get_author(self):
        print("Lester S. Hill")
        return "author"

    def get_cipher_name(self):
        print("keycode Cipher")
        return "cipher name"

    def get_cipher_citation(self):
        return "citation"

    def get_pseudocode(self):
        pc = "insert the encryption pseudocode\n"
        # Inverse_Keycode = scramble Keycode
        # New_inverse = unscramble keycode 
        # for {
            # if 1 < 2  scramble code
            # else: 2 > 1 unscramble code 
        # }
    pc += "insert the decryption pseudocode\n"
    return pc

def main():
    keycode = KeycodeCipher()
    plaintext = 'Please enter your password?'
    keyword = 'Fatcat2345$'
    
    encrypted_text = keycode.encrypt(plaintext, keyword)
    print("Encrypted:", encrypted_text)

    decrypted_text = keycode.decrypt(encrypted_text, keyword)
    print("Decrypted:", decrypted_text)

if __name__ == '__main__':
    main()