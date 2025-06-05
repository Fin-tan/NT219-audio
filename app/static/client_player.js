class ChaoticStreamCipher_js {
    constructor(seed = 0.6, mu = 3.99) {
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

async function startPlayback() {
    const track = document.getElementById('trackSelect').value;
    const mode = document.querySelector('input[name="mode"]:checked').value;
    const audioPlayer = document.getElementById('audioPlayer');
    const ext = track.split('.').pop().toLowerCase();
    let contentType = (ext === 'wav') ? 'audio/wav' : 'audio/mpeg';

    // Reset audio
    audioPlayer.pause();
    audioPlayer.removeAttribute('src');
    audioPlayer.load();

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
    const source = new MediaSource();
    audioPlayer.src = URL.createObjectURL(source);

    source.addEventListener('sourceopen', async () => {
        const mimeCodec = 'audio/mpeg'; // Đảm bảo MIME type này đúng với dữ liệu giải mã
        const buffer = source.addSourceBuffer(mimeCodec);
        
        // Theo dõi trạng thái của SourceBuffer để biết khi nào nó sẵn sàng
        // và khi nào có thể thêm chunk tiếp theo
        buffer.addEventListener('updateend', () => {
            // Khi buffer hoàn thành việc cập nhật (thêm chunk)
            // Nếu đủ dữ liệu trong buffer và chưa phát, bắt đầu phát
            if (!audioPlayer.paused && audioPlayer.currentTime === 0 && buffer.buffered.length > 0) {
                // Kiểm tra xem đã có dữ liệu trong buffer chưa
                // và trình phát đang ở trạng thái dừng và chưa phát
                // Nếu có đủ dữ liệu, bắt đầu phát
                audioPlayer.play().catch(e => console.error("Lỗi khi play audio:", e));
            }
        });

        const response = await fetch(`/stream/${track}/chaotic`);
        const reader = response.body.getReader();

        let isPlaying = false; // Biến cờ để kiểm soát việc gọi play()

        while (true) {
            const { done, value } = await reader.read();
            if (done) {
                // Đợi cho SourceBuffer xử lý hết các chunk cuối cùng
                // trước khi kết thúc stream
                if (!buffer.updating) {
                    source.endOfStream();
                    console.log("[Chaotic] Hết chunk → endOfStream()");
                } else {
                    // Đợi updateend cuối cùng nếu buffer vẫn đang cập nhật
                    buffer.addEventListener('updateend', () => {
                        source.endOfStream();
                        console.log("[Chaotic] Hết chunk → endOfStream() sau updateend");
                    }, { once: true });
                }
                break;
            }

            console.log(`[Chaotic] Nhận chunk ${value.length} byte`);
            const decrypted = scc.decrypt(value);
            
            // Đợi SourceBuffer hoàn thành việc cập nhật trước khi thêm chunk mới
            // Điều này là **quan trọng** để tránh lỗi InvalidStateError
            // khi appendBuffer trong khi buffer đang bận
            while (buffer.updating) {
                await new Promise(resolve => setTimeout(resolve, 10)); // Đợi một chút
            }

            try {
                buffer.appendBuffer(decrypted);
                // Bắt đầu phát ngay khi có chunk đầu tiên được thêm thành công
                if (!isPlaying && audioPlayer.paused && buffer.buffered.length > 0) {
                     // Kiểm tra xem có ít nhất một đoạn dữ liệu trong buffer
                    audioPlayer.play().catch(e => console.error("Lỗi khi play audio (early):", e));
                    isPlaying = true; // Đánh dấu đã bắt đầu phát
                }
            } catch (e) {
                console.error("Lỗi khi appendBuffer:", e);
                // Xử lý lỗi, có thể dừng stream hoặc thử lại
                source.endOfStream("decode"); // Kết thúc stream với lỗi giải mã
                break;
            }
        }
    });
}

    // Fallback: giải mã toàn bộ rồi tạo Blob
    async function fallbackChaoticFullDecode() {
        console.warn("[Chaotic-Fallback] Decode toàn bộ rồi tạo Blob rồi play");
        const scc = new ChaoticStreamCipher_js(0.6, 3.99);
        const response = await fetch(`/stream/${track}/chaotic`);
        const reader = response.body.getReader();
        const chunks = [];
        while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            if (!value) continue;
            chunks.push(scc.decrypt(value));
        }
        const blob = new Blob(chunks, { type: contentType });
        audioPlayer.src = URL.createObjectURL(blob);
        audioPlayer.play();
    }
}
