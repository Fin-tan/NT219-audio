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

function hexStringToUint8Array(hex) {
    const length = hex.length / 2;
    const u8 = new Uint8Array(length);
    for (let i = 0; i < length; i++) {
        u8[i] = parseInt(hex.substr(i * 2, 2), 16);
    }
    return u8;
}

document.getElementById('playButton').addEventListener('click', startPlayback);

async function startPlayback() {
    const trackSelect = document.getElementById('trackSelect');
    const mode = document.querySelector('input[name="mode"]:checked').value;
    const audioPlayer = document.getElementById('audioPlayer');
    const track = trackSelect.value;

    audioPlayer.pause();
    audioPlayer.src = '';

    // Kiểm tra login (JS client-side)
    // Tùy thuộc vào cách bạn xử lý xác thực trên client
    // Hiện tại Flask sẽ chuyển hướng nếu chưa login, nên phần này có thể không cần thiết
    // nhưng tốt để có nếu bạn có logic JS phức tạp hơn.

    if (mode === 'plain') {
        audioPlayer.src = `/static/${track}`;
        audioPlayer.play();

    } else if (mode === 'aes') {
        // Giữ nguyên logic AES (chú ý vấn đề lưu key trong localStorage)
        // Trong hệ thống thực tế, bạn cũng sẽ lấy key AES theo session
        const response = await fetch(`/stream/${track}/aes_encrypted`); // Đổi tên route để khớp với server
        const arrayBuffer = await response.arrayBuffer();
        const encryptedBytes = new Uint8Array(arrayBuffer);
        const key = localStorage.getItem('aesKey'); // Key vẫn đang lấy từ localStorage
        const iv = encryptedBytes.slice(0, 16);
        const data = encryptedBytes.slice(16);
        
        try {
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
        } catch (e) {
            console.error("Lỗi giải mã AES. Key hoặc dữ liệu có thể không đúng:", e);
            alert("Không thể giải mã file AES. Vui lòng kiểm tra khóa hoặc file.");
        }

    } else if (mode === 'chaotic') {
        // --- BƯỚC MỚI: Yêu cầu seed từ Server ---
        let chaoticSeed = null;
        try {
            const keyResponse = await fetch('/get_chaotic_session_key');
            if (!keyResponse.ok) {
                if (keyResponse.status === 401) {
                    alert('Bạn chưa đăng nhập hoặc phiên đã hết hạn. Vui lòng đăng nhập lại.');
                    window.location.href = '/login'; // Chuyển hướng về trang login
                    return;
                }
                throw new Error(`Server returned status ${keyResponse.status}`);
            }
            const keyData = await keyResponse.json();
            chaoticSeed = keyData.seed;
            const chaoticMu = keyData.mu;
            console.log(`[CLIENT] Đã nhận Chaotic Seed từ server: ${chaoticSeed}, Mu: ${chaoticMu}`);
            // Lưu ý: Chúng ta không lưu seed này vào localStorage nữa, nó chỉ tồn tại trong bộ nhớ
            // và được dùng ngay cho phiên này.
        } catch (e) {
            console.error("Lỗi khi lấy Chaotic Seed từ server:", e);
            alert("Không thể lấy khóa streaming. Vui lòng thử lại.");
            return;
        }
        // ------------------------------------------

        const scc = new ChaoticStreamCipher_js(chaoticSeed, 3.99); // Sử dụng seed từ server
        const source = new MediaSource();
        audioPlayer.src = URL.createObjectURL(source);
        
        source.addEventListener('sourceopen', async () => {
            const mimeCodec = 'audio/mpeg'; 
            const buffer = source.addSourceBuffer(mimeCodec);
            
            buffer.addEventListener('updateend', () => {
                if (!audioPlayer.paused && audioPlayer.currentTime === 0 && buffer.buffered.length > 0) {
                    audioPlayer.play().catch(e => console.error("Lỗi khi play audio:", e));
                }
            });

            const response = await fetch(`/stream/${track}/chaotic`);
            const reader = response.body.getReader();

            let isPlaying = false; 
            let chunkCount = 0;

            while (true) {
                const { done, value } = await reader.read();
                if (done) {
                    if (!buffer.updating) {
                        source.endOfStream();
                        console.log("[Chaotic] Hết chunk → endOfStream()");
                    } else {
                        buffer.addEventListener('updateend', () => {
                            source.endOfStream();
                            console.log("[Chaotic] Hết chunk → endOfStream() sau updateend");
                        }, { once: true });
                    }
                    break;
                }
                
                chunkCount++; 
                console.log(`[Chaotic] Nhận chunk ${value.length} byte (Chunk #${chunkCount})`);
                
                const decrypted = scc.decrypt(value); 

                // In plain text đã giải mã (cho debug)
                console.log(`[Chaotic] Decrypted Plain Bytes (first 50 of chunk): ${decrypted.slice(0, 50).join(', ')}...`);
                
                while (buffer.updating) {
                    await new Promise(resolve => setTimeout(resolve, 10));
                }

                try {
                    buffer.appendBuffer(decrypted);
                    if (!isPlaying && audioPlayer.paused && buffer.buffered.length > 0) {
                        audioPlayer.play().catch(e => console.error("Lỗi khi play audio (early):", e));
                        isPlaying = true;
                    }
                } catch (e) {
                    console.error("Lỗi khi appendBuffer:", e);
                    source.endOfStream("decode");
                    break;
                }
            }
        });
    } else if (mode === 'aeschaotic') {
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