/**
 * =====================================================
 * KRIPTOGRAFI ASIMETRIS - RSA-OAEP
 * =====================================================
 */

let rsaKeyPair = null;

// Konversi ArrayBuffer ke Base64
function bufferToBase64(buffer) {
    return btoa(String.fromCharCode(...new Uint8Array(buffer)));
}

// Konversi Base64 ke ArrayBuffer
function base64ToBuffer(base64) {
    return Uint8Array.from(atob(base64), c => c.charCodeAt(0));
}

// Generate pasangan kunci RSA
document.getElementById("generateKeyButton").addEventListener("click", async () => {
    rsaKeyPair = await crypto.subtle.generateKey(
        {
            name: "RSA-OAEP",
            modulusLength: 2048,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: "SHA-256"
        },
        true,
        ["encrypt", "decrypt"]
    );

    const publicKey = await crypto.subtle.exportKey("spki", rsaKeyPair.publicKey);
    const privateKey = await crypto.subtle.exportKey("pkcs8", rsaKeyPair.privateKey);

    document.getElementById("publicKeyOutput").value = bufferToBase64(publicKey);
    document.getElementById("privateKeyOutput").value = bufferToBase64(privateKey);
});

// Enkripsi menggunakan public key
document.getElementById("encryptButton").addEventListener("click", async () => {
    const message = document.getElementById("plaintext").value;

    if (!rsaKeyPair) {
        alert("Generate RSA key terlebih dahulu");
        return;
    }

    const encrypted = await crypto.subtle.encrypt(
        { name: "RSA-OAEP" },
        rsaKeyPair.publicKey,
        new TextEncoder().encode(message)
    );

    document.getElementById("ciphertextOutput").value =
        bufferToBase64(encrypted);
});

// Dekripsi menggunakan private key
document.getElementById("decryptButton").addEventListener("click", async () => {
    try {
        const ciphertext = base64ToBuffer(
            document.getElementById("ciphertextOutput").value
        );

        const decrypted = await crypto.subtle.decrypt(
            { name: "RSA-OAEP" },
            rsaKeyPair.privateKey,
            ciphertext
        );

        document.getElementById("plaintextOutput").textContent =
            new TextDecoder().decode(decrypted);

    } catch {
        alert("Dekripsi gagal");
    }
});
