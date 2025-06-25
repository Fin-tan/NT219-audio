const SLIDING_WINDOW = 30; // giữ lại 30s âm thanh đã phát
const PAST_WINDOW   = 10;  // Giữ lại tối đa 10s âm thanh đã phát
const AHEAD_WINDOW  = 15;  // Giữ lại tối đa 15s âm thanh sắp phát
const CHUNK_DELAY_MS = 300; // chờ 300ms trước khi đọc chunk mới nếu buffer full

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

// Helper: PEM to ArrayBuffer
function pemToArrayBuffer(pem) {
    const b64 = pem.replace(/-----(BEGIN|END)[\w\s]+-----/g, '').replace(/\s+/g, '');
    const bin = atob(b64);
    const arr = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
    return arr.buffer;
}

window.addEventListener('DOMContentLoaded', () => {
   const btn = document.getElementById('playButton');
   if (btn) btn.addEventListener('click', startPlayback);
});

let currentMediaSource = null;
let currentAbortController = null; // Thêm biến này để quản lý fetch

async function startPlayback() {
  const trackSelect = document.getElementById('trackSelect');
  const mode = document.querySelector('input[name="mode"]:checked').value;
  const audioPlayer = document.getElementById('audioPlayer');
  const track = trackSelect.value;

  // --- RESET hoàn toàn trước khi play lại ---
  audioPlayer.pause();
  audioPlayer.removeAttribute('src');
  audioPlayer.load();

  // Hủy MediaSource cũ nếu có
  if (currentMediaSource) {
    try {
      currentMediaSource.endOfStream();
    } catch {}
    currentMediaSource = null;
  }

  // Hủy fetch cũ nếu có
  if (currentAbortController) {
    currentAbortController.abort();
    currentAbortController = null;
  }

  if (mode === 'plain') {
    audioPlayer.src = `/static/${track}`;
    audioPlayer.play();

  } else if (mode === 'chaotic') {
    // 1) ECDH/AES-GCM to get initial seed
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

    // 2) Setup MediaSource for streaming
    const mediaSource = new MediaSource();
    currentMediaSource = mediaSource;
    audioPlayer.src = URL.createObjectURL(mediaSource);

    // Tạo AbortController mới cho fetch này
    const abortController = new AbortController();
    currentAbortController = abortController;

    mediaSource.addEventListener('sourceopen', async () => {
      const sourceBuffer = mediaSource.addSourceBuffer('audio/mpeg');
      // Sử dụng signal để abort fetch khi chuyển bài
      const response = await fetch(`/stream/${track}/chaotic`, { signal: abortController.signal });
      const reader = response.body.getReader();
      let isPlaying = false;
      let readBuffer = new Uint8Array(0);

      try {
        while (true) {
          // Throttle như trước...
          if (audioPlayer.buffered.length) {
            const ahead = audioPlayer.buffered.end(audioPlayer.buffered.length - 1) - audioPlayer.currentTime;
            if (ahead > AHEAD_WINDOW) {
              await new Promise(r => setTimeout(r, CHUNK_DELAY_MS));
              continue;
            }
          }

          const { done, value } = await reader.read();
          if (done) {
            mediaSource.endOfStream();
            break;
          }
          // Append vào readBuffer
          const newBuf = new Uint8Array(readBuffer.length + value.length);
          newBuf.set(readBuffer, 0);
          newBuf.set(value, readBuffer.length);
          readBuffer = newBuf;

          // Try parse as many full chunks as có thể
          let offset = 0;
          while (readBuffer.length - offset >= 4) {
            const view = new DataView(readBuffer.buffer, offset, 4);
            const lengthField = view.getUint32(0); // network-order
            if (readBuffer.length - offset < 4 + lengthField) {
              break; // chưa đủ dữ liệu cho chunk này
            }
            // Tách chunk
            const chunk = readBuffer.slice(offset + 4, offset + 4 + lengthField);
            // Lấy seed và encryptedFrame
            const seedBuf = chunk.slice(0, 8);
            const frameSeed = new DataView(seedBuf.buffer).getFloat64(0);
            const encryptedFrame = chunk.slice(8);
            // Giải mã
            const frameCipher = new ChaoticStreamCipher_js(frameSeed, 3.99);
            const decryptedFrame = frameCipher.decrypt(encryptedFrame);

            // AppendBuffer khi sourceBuffer sẵn sàng
            await new Promise(r => {
              if (!sourceBuffer.updating) return r();
              sourceBuffer.addEventListener('updateend', r, { once: true });
            });
            try {
              sourceBuffer.appendBuffer(decryptedFrame);
            } catch (e) {
              console.error('appendBuffer error:', e);
              mediaSource.endOfStream('decode');
              return;
            }
            if (!isPlaying && audioPlayer.paused && sourceBuffer.buffered.length) {
              audioPlayer.play().catch(err => console.error('play error:', err));
              isPlaying = true;
            }
            offset += 4 + lengthField;
          }
          // Giữ lại phần dư (incomplete) vào readBuffer
          if (offset > 0) {
            readBuffer = readBuffer.slice(offset);
          }
        }
      } catch (err) {
        if (err.name === 'AbortError') {
          // Đã chuyển bài, fetch bị abort, không báo lỗi
        } else {
          console.error('Streaming error:', err);
        }
      }
    });
  }
}
