async function getKey(password){

    const encoder = new TextEncoder();

    const passwordKey =
        await crypto.subtle.importKey(
            "raw",
            encoder.encode(password),
            "PBKDF2",
            false,
            ["deriveKey"]
        );

    return crypto.subtle.deriveKey(
        {
            name:"PBKDF2",
            salt:encoder.encode("vaultSalt"),
            iterations:100000,
            hash:"SHA-256"
        },
        passwordKey,
        {
            name:"AES-GCM",
            length:256
        },
        false,
        ["encrypt","decrypt"]
    );
}

async function encryptText(){

    const password =
        document.getElementById("password").value;

    const text =
        document.getElementById("plaintext").value;

    const key = await getKey(password);

    const iv = crypto.getRandomValues(
        new Uint8Array(12)
    );

    const encrypted =
        await crypto.subtle.encrypt(
            {
                name:"AES-GCM",
                iv:iv
            },
            key,
            new TextEncoder().encode(text)
        );

    const combined =
        new Uint8Array(iv.length + encrypted.byteLength);

    combined.set(iv);
    combined.set(
        new Uint8Array(encrypted),
        iv.length
    );

    document.getElementById("output").value =
        btoa(String.fromCharCode(...combined));
}

async function decryptText(){

    try{

        const password =
            document.getElementById("password").value;

        const cipher =
            document.getElementById("output").value;

        const data =
            Uint8Array.from(
                atob(cipher),
                c => c.charCodeAt(0)
            );

        const iv = data.slice(0,12);
        const encrypted = data.slice(12);

        const key = await getKey(password);

        const decrypted =
            await crypto.subtle.decrypt(
                {
                    name:"AES-GCM",
                    iv:iv
                },
                key,
                encrypted
            );

        document.getElementById("plaintext").value =
            new TextDecoder().decode(decrypted);

    }catch{
        alert("Incorrect password");
    }
}