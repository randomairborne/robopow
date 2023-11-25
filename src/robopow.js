const Robopow = (function () {
    function numToHex(number, radix, zeropad) {
        return number.toString(radix).padStart(zeropad, "0")
    }

    async function findNonce(token, challenge, zerobits) {
        const start = performance.now();
        let nonce = 0
        while (true) {
            const stringNonce = nonce;
            const msgUint8 = new TextEncoder().encode(stringNonce.toString() + token + challenge);
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

    async function verifyCaptcha(apiUrl, config) {
        const configParams = new URLSearchParams(config).toString();
        const challengeRequest = await fetch(`${apiUrl}/v0/challenge?${configParams}`);
        const resp = await challengeRequest.json();
        const token = resp['token'];
        const params = resp['params'];
        const challenges = resp['challenges'];
        const zeros = params['zeros'];

        let challengeResponses = [];
        const start = performance.now();
        for (let i = 0; i < challenges.length; i++) {
            const challenge = challenges[i];
            const nonce = await findNonce(token, challenge, zeros);
            challengeResponses.push(nonce);
        }
        const end = performance.now();
        const duration = end - start;
        console.log(`Robopow round took ${duration}ms to solve ${challenges.length} challenges`);
        console.debug(JSON.stringify(challengeResponses))
        return {
            params,
            token,
            nonces: challengeResponses
        }
    }

    return {
        verifyCaptcha
    }
}());