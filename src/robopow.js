const Robopow = (function () {
    function numToHex(number, radix, zeropad) {
        return number.toString(radix).padStart(zeropad, "0")
    }

    async function findNonce(token, zerobits) {
        const start = performance.now();
        let nonce = 0
        while (true) {
            const stringNonce = nonce;
            const msgUint8 = new TextEncoder().encode(stringNonce.toString() + token);
            const hashBuffer = await crypto.subtle.digest("SHA-512", msgUint8);
            const hashArray = Array.from(new Uint8Array(hashBuffer));
            const bits = hashArray
                .map((n) => numToHex(n, 2, 8))
                .join("");
            if (bits.startsWith("0".repeat(zerobits))) {
                break;
            }
            nonce += 1;
        }
        const end = performance.now();
        const duration = end - start;
        console.debug(`Robopow round took ${duration}ms to find ${zerobits} zerobits`);
        return nonce;
    }

    async function verifyCaptcha(apiUrl) {
        const challengeRequest = await fetch(`${apiUrl}/v0/challenge`);
        const challenges = await challengeRequest.json();
        let challengeResponses = [];
        const start = performance.now();
        for (let i = 0; i < challenges.length;  i++) {
            const challenge = challenges[i];
            const requiredZeroBits = challenge['zeros'];
            const token = challenge['token'];
            const nonce = await findNonce(token, requiredZeroBits);
            challengeResponses.push({
                token: token,
                nonce: nonce
            });
        }
        const end = performance.now();
        const duration = end - start;
        console.log(`Robopow round took ${duration}ms to solve all challenges`);
        console.debug(JSON.stringify(challengeResponses))
        return challengeResponses
    }
    return {
        verifyCaptcha
    }
}());