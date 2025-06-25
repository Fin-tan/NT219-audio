const SLIDING_WINDOW = 30; // giữ lại 30s âm thanh đã phát
const PAST_WINDOW   = 5;   // Giữ lại tối đa 5s âm thanh đã phát
const AHEAD_WINDOW  = 10;  // Giữ lại tối đa 10s âm thanh sắp phát
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

async function startPlayback() {
  const trackSelect = document.getElementById('trackSelect');
  const mode = document.querySelector('input[name="mode"]:checked').value;
  const audioPlayer = document.getElementById('audioPlayer');
  const track = trackSelect.value;

  audioPlayer.pause();
  audioPlayer.src = '';

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

    // Setup MediaSource for streaming
    const mediaSource = new MediaSource();
    audioPlayer.src = URL.createObjectURL(mediaSource);

mediaSource.addEventListener('sourceopen', async () => {
  const sourceBuffer = mediaSource.addSourceBuffer('audio/mpeg');
  const reader       = (await fetch(`/stream/${track}/chaotic`)).body.getReader();
  let isPlaying      = false;

  const PAST_WINDOW    = 10;  // giữ 10s buffer cũ
  const AHEAD_WINDOW   = 15;  // tối đa giữ 15s buffer tương lai
  const CHUNK_DELAY_MS = 300; // chờ 300ms trước khi đọc chunk mới nếu buffer full

  while (true) {
    // —— 0) Throttle: chờ nếu ahead buffer đã vượt ngưỡng
    if (audioPlayer.buffered.length) {
      const ahead = audioPlayer.buffered.end(audioPlayer.buffered.length - 1) - audioPlayer.currentTime;
      if (ahead > AHEAD_WINDOW) {
        await new Promise(r => setTimeout(r, CHUNK_DELAY_MS));
        continue; // quay lại kiểm tra trước khi đọc chunk mới
      }
    }

    // —— 1) Đọc chunk
    const { done, value } = await reader.read();
    if (done) {
      mediaSource.endOfStream();
      break;
    }

    // —— 2) Xoá phần quá cũ
    if (!sourceBuffer.updating && audioPlayer.buffered.length) {
      const cur       = audioPlayer.currentTime;
      const bufStart  = audioPlayer.buffered.start(0);
      const removeEnd = cur - PAST_WINDOW;
      if (removeEnd > bufStart) {
        sourceBuffer.remove(bufStart, removeEnd);
        await new Promise(r => sourceBuffer.addEventListener('updateend', r, { once: true }));
      }
    }

    // —— 3) Giải mã frame
    const seedHeader    = value.slice(4, 12);
    const frameSeed     = new DataView(seedHeader.buffer).getFloat64(0);
    const encryptedFrame= value.slice(12);
    const frameCipher   = new ChaoticStreamCipher_js(frameSeed, 3.99);
    const decryptedFrame= frameCipher.decrypt(encryptedFrame);

    // —— 4) Chờ sẵn sàng rồi append
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

    // —— 5) Bắt đầu play nếu chưa
    if (!isPlaying && audioPlayer.paused && sourceBuffer.buffered.length) {
      audioPlayer.play().catch(err => console.error('play error:', err));
      isPlaying = true;
    }
  }
});



    }

}