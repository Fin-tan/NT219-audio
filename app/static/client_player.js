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
        return this.encrypt(data);
    }
}

function hexStringToUint8Array(hex) {
    const length = hex.length / 2;
    const u8 = new Uint8Array(length);
    for (let i = 0; i < length; i++) {
        u8[i] = parseInt(hex.substr(i*2, 2), 16);
    }
    return u8;
}

async function startPlayback() {
    const track = document.getElementById('trackSelect').value;
    const mode = document.querySelector('input[name="mode"]:checked').value;
    const audioPlayer = document.getElementById('audioPlayer');
    const ext = track.split('.').pop().toLowerCase();
    let contentType = (ext === 'wav') ? 'audio/wav' : 'audio/mpeg';
    audioPlayer.pause();
    audioPlayer.src = '';

    if (mode === 'plain') {
        audioPlayer.src = `/static/${track}`;
        audioPlayer.type = contentType;
        audioPlayer.play();
    } else if (mode === 'aes') {
        const response = await fetch(`/stream/${track}/aes`);
        const arrayBuffer = await response.arrayBuffer();
        const encrypted = new Uint8Array(arrayBuffer);
        const keyHex = localStorage.getItem('aesKey');
        if (!keyHex) return alert("Thiếu aesKey trong localStorage");
        const iv = encrypted.slice(0, 16);
        const data = encrypted.slice(16);
        const cryptoKey = await crypto.subtle.importKey(
            'raw', hexStringToUint8Array(keyHex), { name: 'AES-CFB' }, false, ['decrypt']
        );
        const decrypted = await crypto.subtle.decrypt(
            { name: 'AES-CFB', iv: iv }, cryptoKey, data
        );
        const blob = new Blob([decrypted], { type: contentType });
        audioPlayer.src = URL.createObjectURL(blob);
        audioPlayer.play();
    } else if (mode === 'chaotic') {
        const scc = new ChaoticStreamCipher_js(0.6, 3.99);
        const response = await fetch(`/stream/${track}/chaotic`);
        const reader = response.body.getReader();
        const chunks = [];
        while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            chunks.push(scc.decrypt(value));
        }
        const blob = new Blob(chunks, { type: contentType });
        audioPlayer.src = URL.createObjectURL(blob);
        audioPlayer.play();
    }
}