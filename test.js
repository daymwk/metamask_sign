require('./verify.js');
const { ethers } = require('ethers');
const V = globalThis.MMVerify;
let fails = 0;
function check(name, got, want) {
  const ok = String(got).toLowerCase() === String(want).toLowerCase();
  if (!ok) fails++;
  console.log((ok ? 'PASS ' : 'FAIL ') + name + (ok ? '' : `\n   got  ${got}\n   want ${want}`));
}
const enc = s => new TextEncoder().encode(s);
// keccak known vectors (Keccak-256, not SHA3)
check('keccak("")', V.keccak256Hex(enc('')), '0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470');
check('keccak("abc")', V.keccak256Hex(enc('abc')), '0x4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45');
check('keccak(long 200B)', V.keccak256Hex(new Uint8Array(200).fill(0x61)), ethers.keccak256(new Uint8Array(200).fill(0x61)));

// personal_sign vectors from an independent implementation (ethers v6)
const cases = [
  ['0x' + '01'.repeat(32), 'hello'],
  ['0x' + '02'.repeat(32), ''],
  ['0x' + '0f'.repeat(32), 'hello prt.run — éàü 中文'],
  ['0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef', 'a'.repeat(500)],
  ['0x' + '7a'.repeat(32), 'line1\nline2 "quoted" \\ backslash']
];
(async () => {
  for (const [pk, msg] of cases) {
    const w = new ethers.Wallet(pk);
    const sig = await w.signMessage(msg);
    const r = V.verifyPersonal(msg, w.address, sig);
    check(`recover ${w.address.slice(0,10)} msg=${JSON.stringify(msg).slice(0,24)}`, r.recovered, w.address);
    check(`verify ok ${w.address.slice(0,10)}`, r.ok, true);
    // tamper message
    check('tampered message rejected', V.verifyPersonal(msg + 'x', w.address, sig).ok, false);
    // tamper address
    const other = ethers.Wallet.createRandom().address;
    check('wrong address rejected', V.verifyPersonal(msg, other, sig).ok, false);
    // v=0/1 form instead of 27/28
    const s01 = sig.slice(0, -2) + (parseInt(sig.slice(-2), 16) - 27).toString(16).padStart(2, '0');
    check('v=0/1 accepted', V.verifyPersonal(msg, w.address, s01).ok, true);
  }
  // malformed inputs must throw, not silently pass
  for (const bad of ['0xdeadbeef', '0x' + '00'.repeat(65)]) {
    let threw = false;
    try { V.verifyPersonal('hello', '0x' + '11'.repeat(20), bad); } catch (e) { threw = true; }
    check('malformed rejected: ' + bad.slice(0,12), threw, true);
  }
  // case-insensitive address compare
  const w = new ethers.Wallet('0x' + '05'.repeat(32));
  const sig = await w.signMessage('case test');
  check('uppercase address accepted', V.verifyPersonal('case test', w.address.toUpperCase().replace('0X','0x'), sig).ok, true);
  console.log(fails === 0 ? '\nALL PASS' : `\n${fails} FAILURES`);
  process.exit(fails ? 1 : 0);
})();
