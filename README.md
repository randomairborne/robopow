# Robopow

For shooting robots- pew pew!!

Robopow is a CAPTCHA-like service that is designed to stop
DDOS and large-scale automated attacks. It does **not** offer any
protection against malicious users operating at a small scale, or
who have very large budgets. User beware.

It uses a large number of sha512sum nonce calculations. It's kinda cool I guess.

Import the script:

```html

<script src="https://robopow.example.com/api/v0/client.js"></script>
```

Client JS:

```js
// All optional
const settings = {
    zeros: 12, // Number of zero-bits at the start of sums
    challenges: 8, // Number of nonces that must be computed
    timeout: 15, // timeout in seconds. Tune this to your target devices.
};
const {token, nonces} = await Robopow.verifyCaptcha(
    "https://robopow.example.com/api",
);
const request = await fetch(`http://yourapi.example.com/captcha/${token}`, {
    method: "POST",
    body: JSON.stringify(nonces),
    headers: {
        "content-type": "application/json",
    },
});
```

On your server:

```js
const nonces = getRequestJson(); // As long as the order is preserved, you can transmit the nonce list to your server however you want
const token = getPathFragment(); // Ditto the above

// asking the server if the request is valid
const request = await fetch(`https://robopow.example.com/api/v0/verify/${token}`, {
    method: "POST",
    body: JSON.stringify(nonces), // Remember to preserve the order!!
    headers: {
        "content-type": "application/json",
    },
});
const response = await request.json(); // Returns json object, documented below
```

Validate that this response object is equal to the
configuration set in your client JS on your server.
If valid is false, then the client did not properly
solve the challenge, and you should deny the request.

```json
{
  "params": {
    "zeros": 12,
    "challenges": 8,
    "timeout": 15
  },
  "valid": true
}
```
