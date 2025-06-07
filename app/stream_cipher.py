from Crypto.Cipher import AES

class ChaoticStreamCipher:
    def __init__(self, seed, mu):
        # Logistic map parameters
        self.x = seed
        self.mu = mu

    def keystream(self, length):
        """Generate keystream of `length` bytes via logistic map"""
        ks = bytearray()
        for _ in range(length):
            # update chaotic state
            self.x = self.mu * self.x * (1 - self.x)
            # map float in (0,1) to byte
            ks.append(int(self.x * 256) & 0xFF)
        return bytes(ks)

    def encrypt(self, data):
        ks = self.keystream(len(data))
        return bytes(a ^ b for a, b in zip(data, ks))

    def decrypt(self, data):
        # symmetricAESAES
        return self.encrypt(data)