# metamask_sign

Sign a message with MetaMask (`personal_sign`, EIP-191) and verify signatures locally.

## Usage

```bash
python3 -m http.server 8898 --bind 127.0.0.1
# open http://127.0.0.1:8898/index.html
```

Serve it over HTTP: on a `file://` page MetaMask injects nothing, so there is no provider.

Type a message, hit **Sign**, approve in MetaMask. Address, signature and message come back with copy buttons, and the signature is verified right away.

## Verify

- Panel **Vérifier une signature**: paste address + message + signature → verdict and recovered address.
- Etherscan: <https://etherscan.io/verifiedSignatures>

`verify.js` recovers the signer locally (Keccak-256 + secp256k1, plain JS, no dependencies, no network). Accepts 65-byte signatures (`v` as 27/28 or 0/1) and 64-byte EIP-2098 ones.

## Tests

```bash
npm i ethers   # only for the test vectors
node test.js
```
