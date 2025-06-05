async function startPlayback() {
    const trackSelect = document.getElementById('trackSelect');
    const mode = document.querySelector('input[name="mode"]:checked').value;
    const audioPlayer = document.getElementById('audioPlayer');
    const track = trackSelect.value;

    // Tạm dừng nếu đang phát
    audioPlayer.pause();
    audioPlayer.src = '';

    if (mode === 'plain') {
        // Phát file MP3 gốc
        audioPlayer.src = `/static/${track}`;
        audioPlayer.play();

    } else if (mode === 'aes') {
        // Tải file AES đã mã hóa về và giải mã phía client qua JavaScript
        const response = await fetch(`/stream/${track}/aes`);
        const arrayBuffer = await response.arrayBuffer();
        const encryptedBytes = new Uint8Array(arrayBuffer);
        const key = localStorage.getItem('aesKey');
        const iv = encryptedBytes.slice(0, 16);
        const data = encryptedBytes.slice(16);
        
        // Giải mã AES-CFB (dùng Web Crypto API)
        const cryptoKey = await window.crypto.subtle.importKey(
            'raw',
            hexStringToUint8Array(key),
            { name: 'AES-CFB' },
            false,
            ['decrypt']
        );
        const decryptedArrayBuffer = await window.crypto.subtle.decrypt(
            { name: 'AES-CFB', iv: iv },
            cryptoKey,
            data
        );
        const blob = new Blob([decryptedArrayBuffer], { type: 'audio/mpeg' });
        audioPlayer.src = URL.createObjectURL(blob);
        audioPlayer.play();

    } else if (mode === 'chaotic') {
        // Phát streaming từng chunk, giải mã Chaotic Stream Cipher
        const scc = new ChaoticStreamCipher_js(0.6, 3.99);
        const source = new MediaSource();
        audioPlayer.src = URL.createObjectURL(source);
        source.addEventListener('sourceopen', async () => {
            const mimeCodec = 'audio/mpeg';
            const buffer = source.addSourceBuffer(mimeCodec);
            const response = await fetch(`/stream/${track}/chaotic`);
            const reader = response.body.getReader();
            while (true) {
                const { done, value } = await reader.read();
                if (done) {
                    source.endOfStream();
                    break;
                }
                // value là Uint8Array chứa chunk đã mã hóa
                const decrypted = scc.decrypt(value);
                buffer.appendBuffer(decrypted);
            }
            audioPlayer.play();
        });
    }
}

// Helper: chuyển chuỗi hex sang Uint8Array
function hexStringToUint8Array(hex) {
    const length = hex.length / 2;
    const u8 = new Uint8Array(length);
    for (let i = 0; i < length; i++) {
        u8[i] = parseInt(hex.substr(i*2, 2), 16);
    }
    return u8;
}

// ChaoticStreamCipher triển khai bằng JS giống Python
class ChaoticStreamCipher_js {
    constructor(seed = 0.5, mu = 3.99) {
        this.x = seed;
        this.mu = mu;
    }
    keystream(length) {
        const ks = new Uint8Array(length);
        for (let i = 0; i < length; i++) {
            this.x = this.mu * this.x * (1 - this.x);
            ks[i] = (this.x * 256) & 0xFF;
        }
        return ks;
    }
    encrypt(data) {
        const ks = this.keystream(data.length);
        const out = new Uint8Array(data.length);
        for (let i = 0; i < data.length; i++) {
            out[i] = data[i] ^ ks[i];
        }
        return out;
    }
    decrypt(data) {
        return this.encrypt(data); // tính chất xor
    }
}