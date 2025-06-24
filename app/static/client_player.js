class ChaoticStreamCipher_js {
    constructor(seed, mu) {
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
// >>> ECC START: helper chuyển PEM to ArrayBuffer
function pemToArrayBuffer(pem) {
    // loại bỏ header/footer
    const b64 = pem.replace(/-----(BEGIN|END)[\w\s]+-----/g, '').replace(/\s+/g, '');
    const bin = atob(b64);
    const arr = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
    return arr.buffer;
}
// <<< ECC END

function hexStringToUint8Array(hex) {
    const length = hex.length / 2;
    const u8 = new Uint8Array(length);
    for (let i = 0; i < length; i++) {
        u8[i] = parseInt(hex.substr(i * 2, 2), 16);
    }
    return u8;
}
window.addEventListener('DOMContentLoaded', () => {
   const btn = document.getElementById('playButton');
   if (btn) {
     btn.addEventListener('click', startPlayback);
   }
 });

async function startPlayback() {
  const trackSelect = document.getElementById('trackSelect');
  const mode = document.querySelector('input[name="mode"]:checked').value;
  const audioPlayer = document.getElementById('audioPlayer');
  const track = trackSelect.value;

  audioPlayer.pause();
  audioPlayer.src = '';

  if (mode === 'plain') {
    // Plain streaming
    audioPlayer.src = `/static/${track}`;
    audioPlayer.play();
  }
  else if (mode === 'chaotic') {
    // Chaotic streaming per-frame
    // Step 1: ECDH/AES-GCM to get initial seed
    const serverPem = await fetch('/ecdh/server_pub_key').then(r => r.text());
    const serverPubDer = pemToArrayBuffer(serverPem);
    const serverPubKey = await crypto.subtle.importKey(
      'spki', serverPubDer, { name: 'ECDH', namedCurve: 'P-256' }, false, []
    );
    const clientKeyPair = await crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']
    );
    const clientPubRaw = await crypto.subtle.exportKey('raw', clientKeyPair.publicKey);
    const clientPubB64 = btoa(String.fromCharCode(...new Uint8Array(clientPubRaw)));
    const sharedBits = await crypto.subtle.deriveBits(
      { name: 'ECDH', public: serverPubKey }, clientKeyPair.privateKey, 256
    );
    const hkdfKey = await crypto.subtle.importKey(
      'raw', sharedBits, { name: 'HKDF' }, false, ['deriveKey']
    );
    const aesKey = await crypto.subtle.deriveKey(
      { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array([]), info: new TextEncoder().encode('chaotic-seed') },
      hkdfKey,
      { name: 'AES-GCM', length: 256 },
      false,
      ['decrypt']
    );
    const resp = await fetch('/ecdh/request_seed', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ client_pub: clientPubB64 })
    });
    const { iv: iv_b64, encrypted_seed: enc_b64 } = await resp.json();
    const iv = Uint8Array.from(atob(iv_b64), c => c.charCodeAt(0));
    const ciphertext = Uint8Array.from(atob(enc_b64), c => c.charCodeAt(0));
    const seedBuf = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, aesKey, ciphertext);
    const chaoticSeed = parseFloat(new TextDecoder().decode(seedBuf));

    // Step 2: MediaSource + per-frame decrypt
    const mediaSource = new MediaSource();
    audioPlayer.src = URL.createObjectURL(mediaSource);

    mediaSource.addEventListener('sourceopen', async () => {
      const sourceBuffer = mediaSource.addSourceBuffer('audio/mpeg');
      const reader = (await fetch(`/stream/${track}/chaotic`)).body.getReader();
      let isPlaying = false;

      while (true) {
        const { done, value } = await reader.read();
        if (done) {
          await new Promise(r => {
            if (!sourceBuffer.updating) return r();
            sourceBuffer.addEventListener('updateend', r, { once: true });
          });
          mediaSource.endOfStream();
          break;
        }

        // 1) Unpack 8-byte seed
        const header = value.slice(0, 8);
        const seed = new DataView(header.buffer).getFloat64(0);

        // 2) Encrypted frame data
        const encryptedFrame = value.slice(8);

        // 3) Init cipher for this frame
        const frameCipher = new ChaoticStreamCipher_js(seed, 3.99);

        // 4) Decrypt frame
        const decryptedFrame = frameCipher.decrypt(encryptedFrame);

        // 5) Append to SourceBuffer
        await new Promise(r => {
          if (!sourceBuffer.updating) return r();
          sourceBuffer.addEventListener('updateend', r, { once: true });
        });
        try {
          sourceBuffer.appendBuffer(decryptedFrame);
        } catch (e) {
          console.error('appendBuffer error:', e);
          mediaSource.endOfStream('decode');
          break;
        }

        // 6) Auto-play on first data
        if (!isPlaying && audioPlayer.paused && sourceBuffer.buffered.length > 0) {
          audioPlayer.play().catch(err => console.error('play error:', err));
          isPlaying = true;
        }
      }
    });
  }else if (mode === 'aeschaotic') {
        // Hybrid AES-GCM → Chaotic
        let chaoticSeed = null;
        try {
            const keyResp = await fetch('/get_chaotic_session_key');
            if (!keyResp.ok) {
                if (keyResp.status === 401) {
                    alert('Bạn chưa đăng nhập hoặc phiên đã hết hạn.');
                    window.location.href = '/login';
                    return;
                }
                throw new Error(`Server trả status ${keyResp.status}`);
            }
            chaoticSeed = (await keyResp.json()).seed;
        } catch (e) {
            console.error("Lỗi khi lấy Chaotic seed:", e);
            alert("Không thể lấy Chaotic key. Vui lòng thử lại.");
            return;
        }

        const scc = new ChaoticStreamCipher_js(chaoticSeed, 3.99);
        const mediaSource = new MediaSource();
        audioPlayer.src = URL.createObjectURL(mediaSource);

        mediaSource.addEventListener('sourceopen', async () => {
            const mimeCodec = 'audio/mpeg';
            const sourceBuffer = mediaSource.addSourceBuffer(mimeCodec);
            const response = await fetch(`/stream/${track}/aeschaotic`);
            if (!response.ok) {
                console.error("Lỗi khi fetch AES-Chaotic stream:", response.status);
                return;
            }
            const reader = response.body.getReader();
            let isPlaying = false;
            while (true) {
                const { done, value } = await reader.read();
                if (done) {
                    if (!sourceBuffer.updating) {
                        mediaSource.endOfStream();
                    } else {
                        sourceBuffer.addEventListener('updateend', () => mediaSource.endOfStream(), { once: true });
                    }
                    break;
                }
                // Đây là chunk plaintext đã được AES-GCM giải xong trên server, 
                // nhưng sau đó server đã Chaotic-encrypt lại. 
                // Bên client cần Chaotic-decrypt để lấy lại audio gốc.
                const decryptedChunk = scc.decrypt(value);
                while (sourceBuffer.updating) {
                    await new Promise(res => setTimeout(res, 10));
                }
                try {
                    sourceBuffer.appendBuffer(decryptedChunk);
                    if (!isPlaying && audioPlayer.paused && sourceBuffer.buffered.length > 0) {
                        audioPlayer.play().catch(e => console.error("Lỗi khi play audio:", e));
                        isPlaying = true;
                    }
                } catch (e) {
                    console.error("Lỗi appendBuffer (AES-Chaotic):", e);
                    mediaSource.endOfStream("decode");
                    break;
                }
            }
        });
    }

}