/**
 * =====================================================
 * KRIPTOGRAFI SIMETRIS - AES-256-GCM
 * Seluruh proses berjalan di sisi client (browser)
 * =====================================================
 */

async function deriveKeyFromPassword(password, salt) {
    const encoder = new TextEncoder();

    // Import password sebagai material awal kunci
    const keyMaterial = await crypto.subtle.importKey(
        "raw",
        encoder.encode(password),
        "PBKDF2",
        false,
        ["deriveKey"]
    );

    // Turunkan kunci AES menggunakan PBKDF2
    return crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: salt,
            iterations: 100000,
            hash: "SHA-256"
        },
        keyMaterial,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt", "decrypt"]
    );
}

// Konversi ArrayBuffer ke Base64
function bufferToBase64(buffer) {
    return btoa(String.fromCharCode(...new Uint8Array(buffer)));
}

// Konversi Base64 ke ArrayBuffer
function base64ToBuffer(base64) {
    return Uint8Array.from(atob(base64), c => c.charCodeAt(0));
}

// Proses enkripsi
document.getElementById("encryptButton").addEventListener("click", async () => {
    const plaintext = document.getElementById("plaintext").value;
    const password = document.getElementById("password").value;

    if (password.length < 8 || plaintext === "") {
        alert("Password minimal 8 karakter dan pesan tidak boleh kosong");
        return;
    }

    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));

    const key = await deriveKeyFromPassword(password, salt);

    const encrypted = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv },
        key,
        new TextEncoder().encode(plaintext)
    );

    document.getElementById("ciphertextOutput").textContent =
        bufferToBase64(encrypted);
    document.getElementById("ivOutput").textContent =
        bufferToBase64(iv);
    document.getElementById("saltOutput").textContent =
        bufferToBase64(salt);

    // Autofill ke sisi dekripsi
    document.getElementById("decryptCiphertext").value =
        bufferToBase64(encrypted);
    document.getElementById("decryptIV").value =
        bufferToBase64(iv);
    document.getElementById("decryptSalt").value =
        bufferToBase64(salt);
});

// Proses dekripsi
document.getElementById("decryptButton").addEventListener("click", async () => {
    try {
        const password = document.getElementById("decryptPassword").value;
        const ciphertext = base64ToBuffer(
            document.getElementById("decryptCiphertext").value
        );
        const iv = base64ToBuffer(
            document.getElementById("decryptIV").value
        );
        const salt = base64ToBuffer(
            document.getElementById("decryptSalt").value
        );

        const key = await deriveKeyFromPassword(password, salt);

        const decrypted = await crypto.subtle.decrypt(
            { name: "AES-GCM", iv: iv },
            key,
            ciphertext
        );

        document.getElementById("plaintextOutput").textContent =
            new TextDecoder().decode(decrypted);

    } catch {
        alert("Dekripsi gagal. Password salah atau data rusak.");
    }
});
