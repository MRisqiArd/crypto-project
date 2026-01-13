/**
 * =====================================================
 * KRIPTOGRAFI HYBRID
 * RSA-OAEP + AES-256-GCM
 * =====================================================
 */

let rsaKeyPair;
let aesKey;
let iv;
let encryptedData;
let encryptedAESKey;

// Utility Base64
function bufferToBase64(buffer) {
    return btoa(String.fromCharCode(...new Uint8Array(buffer)));
}

function base64ToBuffer(base64) {
    return Uint8Array.from(atob(base64), c => c.charCodeAt(0));
}

// STEP 1: Generate RSA Key Pair
document.getElementById("generateRSAButton").addEventListener("click", async () => {
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

    document.getElementById("publicKeyOutput").value =
        bufferToBase64(await crypto.subtle.exportKey("spki", rsaKeyPair.publicKey));

    document.getElementById("privateKeyOutput").value =
        bufferToBase64(await crypto.subtle.exportKey("pkcs8", rsaKeyPair.privateKey));
});

// STEP 2: Hybrid Encryption
document.getElementById("encryptHybridButton").addEventListener("click", async () => {
    if (!rsaKeyPair) {
        alert("Generate RSA key terlebih dahulu");
        return;
    }

    const message = document.getElementById("plaintext").value;

    // Generate AES key
    aesKey = await crypto.subtle.generateKey(
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt"]
    );

    iv = crypto.getRandomValues(new Uint8Array(12));

    // Enkripsi data dengan AES
    encryptedData = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv },
        aesKey,
        new TextEncoder().encode(message)
    );

    // Enkripsi kunci AES dengan RSA public key
    const exportedAESKey = await crypto.subtle.exportKey("raw", aesKey);

    encryptedAESKey = await crypto.subtle.encrypt(
        { name: "RSA-OAEP" },
        rsaKeyPair.publicKey,
        exportedAESKey
    );

    document.getElementById("encryptedDataOutput").value =
        bufferToBase64(encryptedData);

    document.getElementById("encryptedAESKeyOutput").value =
        bufferToBase64(encryptedAESKey);

    document.getElementById("ivOutput").value =
        bufferToBase64(iv);
});

// STEP 3: Hybrid Decryption
document.getElementById("decryptHybridButton").addEventListener("click", async () => {
    try {
        // Dekripsi kunci AES menggunakan RSA private key
        const decryptedAESKeyRaw = await crypto.subtle.decrypt(
            { name: "RSA-OAEP" },
            rsaKeyPair.privateKey,
            encryptedAESKey
        );

        const importedAESKey = await crypto.subtle.importKey(
            "raw",
            decryptedAESKeyRaw,
            { name: "AES-GCM", length: 256 },
            false,
            ["decrypt"]
        );

        // Dekripsi data menggunakan AES
        const decryptedData = await crypto.subtle.decrypt(
            { name: "AES-GCM", iv: iv },
            importedAESKey,
            encryptedData
        );

        document.getElementById("plaintextOutput").textContent =
            new TextDecoder().decode(decryptedData);

    } catch {
        alert("Dekripsi gagal");
    }
});
