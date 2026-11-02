/* Pure-JS Keccak-256 + secp256k1 public-key recovery for EIP-191 (personal_sign).
   No dependencies, BigInt only. Used by index.html to verify a signature locally. */
(function (root) {
  "use strict";

  // ---------- Keccak-256 (original Keccak padding 0x01, not SHA3's 0x06) ----------
  var MASK = (1n << 64n) - 1n;
  var RC = [
    0x0000000000000001n, 0x0000000000008082n, 0x800000000000808an, 0x8000000080008000n,
    0x000000000000808bn, 0x0000000080000001n, 0x8000000080008081n, 0x8000000000008009n,
    0x000000000000008an, 0x0000000000000088n, 0x0000000080008009n, 0x000000008000000an,
    0x000000008000808bn, 0x800000000000008bn, 0x8000000000008089n, 0x8000000000008003n,
    0x8000000000008002n, 0x8000000000000080n, 0x000000000000800an, 0x800000008000000an,
    0x8000000080008081n, 0x8000000000008080n, 0x0000000080000001n, 0x8000000080008008n
  ];
  var ROT = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14]
  ];

  function rotl(x, n) {
    if (n === 0) return x;
    var k = BigInt(n);
    return ((x << k) | (x >> (64n - k))) & MASK;
  }

  function permute(A) {
    var C = new Array(5), B = new Array(25), x, y, D, i;
    for (var round = 0; round < 24; round++) {
      for (x = 0; x < 5; x++) C[x] = A[x] ^ A[x + 5] ^ A[x + 10] ^ A[x + 15] ^ A[x + 20];
      for (x = 0; x < 5; x++) {
        D = C[(x + 4) % 5] ^ rotl(C[(x + 1) % 5], 1);
        for (y = 0; y < 5; y++) A[x + 5 * y] ^= D;
      }
      for (x = 0; x < 5; x++) {
        for (y = 0; y < 5; y++) {
          i = x + 5 * y;
          B[y + 5 * ((2 * x + 3 * y) % 5)] = rotl(A[i], ROT[x][y]);
        }
      }
      for (x = 0; x < 5; x++) {
        for (y = 0; y < 5; y++) {
          i = x + 5 * y;
          A[i] = B[i] ^ (~B[(x + 1) % 5 + 5 * y] & MASK & B[(x + 2) % 5 + 5 * y]);
        }
      }
      A[0] ^= RC[round];
    }
  }

  function keccak256(bytes) {
    var rate = 136;
    var padLen = Math.ceil((bytes.length + 1) / rate) * rate;
    var p = new Uint8Array(padLen);
    p.set(bytes);
    p[bytes.length] ^= 0x01;
    p[padLen - 1] ^= 0x80;
    var A = new Array(25).fill(0n), i, b, lane, off;
    for (off = 0; off < padLen; off += rate) {
      for (i = 0; i < rate / 8; i++) {
        lane = 0n;
        for (b = 7; b >= 0; b--) lane = (lane << 8n) | BigInt(p[off + i * 8 + b]);
        A[i] ^= lane;
      }
      permute(A);
    }
    var out = new Uint8Array(32);
    for (i = 0; i < 4; i++) {
      lane = A[i];
      for (b = 0; b < 8; b++) { out[i * 8 + b] = Number(lane & 0xffn); lane >>= 8n; }
    }
    return out;
  }

  // ---------- secp256k1 ----------
  var P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;
  var N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
  var GX = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n;
  var GY = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n;
  var G = { x: GX, y: GY };

  function mod(a, m) { var r = a % m; return r >= 0n ? r : r + m; }

  function inv(a, m) {
    var g = m, x = 1n, y = 0n, u = mod(a, m), v = g, q, t;
    while (u !== 0n) {
      q = v / u;
      t = v - q * u; v = u; u = t;
      t = y - q * x; y = x; x = t;
    }
    if (v !== 1n) throw new Error("not invertible");
    return mod(y, m);
  }

  function powMod(base, exp, m) {
    var r = 1n; base = mod(base, m);
    while (exp > 0n) {
      if (exp & 1n) r = (r * base) % m;
      base = (base * base) % m;
      exp >>= 1n;
    }
    return r;
  }

  function add(p1, p2) {
    if (p1 === null) return p2;
    if (p2 === null) return p1;
    if (p1.x === p2.x) {
      if (mod(p1.y + p2.y, P) === 0n) return null;
      return dbl(p1);
    }
    var l = mod((p2.y - p1.y) * inv(p2.x - p1.x, P), P);
    var x = mod(l * l - p1.x - p2.x, P);
    return { x: x, y: mod(l * (p1.x - x) - p1.y, P) };
  }

  function dbl(p1) {
    if (p1 === null || p1.y === 0n) return null;
    var l = mod(3n * p1.x * p1.x * inv(2n * p1.y, P), P);
    var x = mod(l * l - 2n * p1.x, P);
    return { x: x, y: mod(l * (p1.x - x) - p1.y, P) };
  }

  function mul(point, k) {
    var r = null, addend = point;
    k = mod(k, N);
    while (k > 0n) {
      if (k & 1n) r = add(r, addend);
      addend = dbl(addend);
      k >>= 1n;
    }
    return r;
  }

  function bytesToBig(b) {
    var v = 0n;
    for (var i = 0; i < b.length; i++) v = (v << 8n) | BigInt(b[i]);
    return v;
  }

  function bigToBytes(v, len) {
    var out = new Uint8Array(len);
    for (var i = len - 1; i >= 0; i--) { out[i] = Number(v & 0xffn); v >>= 8n; }
    return out;
  }

  function hexToBytes(hex) {
    var h = String(hex).replace(/^0x/i, "").trim();
    if (h.length % 2) h = "0" + h;
    if (!/^[0-9a-fA-F]*$/.test(h)) throw new Error("hex invalide");
    var out = new Uint8Array(h.length / 2);
    for (var i = 0; i < out.length; i++) out[i] = parseInt(h.substr(i * 2, 2), 16);
    return out;
  }

  function bytesToHex(b) {
    var s = "";
    for (var i = 0; i < b.length; i++) s += b[i].toString(16).padStart(2, "0");
    return "0x" + s;
  }

  function concat(a, b) {
    var out = new Uint8Array(a.length + b.length);
    out.set(a); out.set(b, a.length);
    return out;
  }

  // EIP-191 version 0x45 ("Ethereum Signed Message")
  function personalHash(messageBytes) {
    var prefix = new TextEncoder().encode(
      "\x19Ethereum Signed Message:\n" + messageBytes.length
    );
    return keccak256(concat(prefix, messageBytes));
  }

  // signature: 65 bytes (r || s || v) or 64 bytes (EIP-2098 compact)
  function recoverAddress(hash, sig) {
    var r, s, v;
    if (sig.length === 65) {
      r = bytesToBig(sig.subarray(0, 32));
      s = bytesToBig(sig.subarray(32, 64));
      v = sig[64];
      if (v >= 27) v -= 27;
    } else if (sig.length === 64) {
      var sOrV = sig[32];
      v = (sOrV & 0x80) ? 1 : 0;
      sig = sig.slice();
      sig[32] = sOrV & 0x7f;
      r = bytesToBig(sig.subarray(0, 32));
      s = bytesToBig(sig.subarray(32, 64));
    } else {
      throw new Error("signature de longueur invalide (" + sig.length + " octets)");
    }
    if (v !== 0 && v !== 1) throw new Error("v invalide (" + v + ")");
    if (r <= 0n || r >= N || s <= 0n || s >= N) throw new Error("r/s hors domaine");

    var alpha = mod(r * r * r + 7n, P);
    var y = powMod(alpha, (P + 1n) / 4n, P);
    if ((y & 1n) !== BigInt(v)) y = P - y;
    if (mod(y * y, P) !== alpha) throw new Error("clé publique impossible (r non valide pour cette courbe)");
    var R = { x: r, y: y };

    var e = mod(bytesToBig(hash), N);
    var rInv = inv(r, N);
    // Q = r^-1 * (s*R - e*G)
    var sR = mul(R, s);
    var neG = mul(G, mod(-e, N));
    var Q = mul(add(sR, neG), rInv);
    if (Q === null) throw new Error("clé publique à l'infini");

    var pub = concat(bigToBytes(Q.x, 32), bigToBytes(Q.y, 32));
    var addr = keccak256(pub).subarray(12);
    return bytesToHex(addr);
  }

  function verifyPersonal(message, address, signature) {
    var hash = personalHash(new TextEncoder().encode(message));
    var recovered = recoverAddress(hash, hexToBytes(signature));
    var ok = recovered.toLowerCase() === String(address).trim().toLowerCase();
    return { ok: ok, recovered: recovered };
  }

  root.MMVerify = {
    keccak256: keccak256,
    keccak256Hex: function (bytes) { return bytesToHex(keccak256(bytes)); },
    personalHash: personalHash,
    recoverAddress: recoverAddress,
    verifyPersonal: verifyPersonal,
    hexToBytes: hexToBytes,
    bytesToHex: bytesToHex
  };
})(typeof window !== "undefined" ? window : globalThis);
