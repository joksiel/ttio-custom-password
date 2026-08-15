const WebSocket = require('ws');
const readline = require("readline");

// modified version of the games packet writer
class BitWriter {
  constructor() {
    this.size = 0;
    this.bitPosition = 0;
    this.buffer = null;
  }
  init(buffer) {
    this.bitPosition = 0;
    this.buffer = buffer;
    this.size = buffer.length;
  }
  allocateAndInitialize(totalBits) {
    this.init(new Uint8Array((totalBits + 7) >> 3));
    return this.buffer;
  }
  writeBits(bitCount, value) {
    const end = this.bitPosition + bitCount - 1;
    for (let i = this.bitPosition; i <= end; i++)
      this.buffer[i >> 3] |= ((value >> (end - i)) & 1) << (7 - (i & 7));
    this.bitPosition += bitCount;
    if (this.bitPosition > 8 * this.size) console.error("Wrapper Overflow");
  }
  toHex() {
    return Array.from(this.buffer).map(b => b.toString(16).padStart(2, '0')).join('');
  }
}
// utility needed for encoding mostly credentials
const encode_6_bits = (char) => {
  const code = char.charCodeAt(0);
  if (code === 45) return 0;
  if (code === 95) return 37;
  if (code >= 48 && code <= 57) return code - 48 + 1;
  if (code >= 65 && code <= 90) return code - 65 + 11;
  if (code >= 97 && code <= 122) return code - 97 + 38;
  return 0;
}
class password_packet {
  constructor(new_password) {
    const password = this.sanitize(new_password);
   const dw = new BitWriter();
   dw.allocateAndInitialize(1 + 6 + 90);
   dw.writeBits(1, 0); dw.writeBits(6, 18);
    const six_bits = password.split('').map(encode_6_bits);
    for (const value of six_bits) {
      dw.writeBits(6, value);
    }
    return dw.buffer;
  }
  sanitize(password) {
    // trim password to 15 bytes if needed
    if (password.length > 15) {
      return password.substring(0, 15);
    }
    // fill missing space with '-'s (e.g. david -> ----------david)
    while (password.length < 15) {
      password = '-' + password;
    }
    console.log(`[i] sanitized password: ${password}`);
    return password;
  }
}
// modified version of the games packet reader
class BitReader {
  init(buffer) {
    this.buffer = buffer;
    this.size = buffer.length;
    this.bitPosition = 0;
  }
  readBits(size) {
    let value = 0;
    const end = this.bitPosition + size - 1;
    for (let i = this.bitPosition; i <= end; i++)
      value |= ((this.buffer[i >> 3] >> (7 - (i & 7))) & 1) << (end - i);
    this.bitPosition += size;
    if (this.bitPosition > 8 * this.size) console.error("Reader Overflow");
    return value;
  }
}
// PoW challenge solver
class HashGenerator {
  constructor() { this.BUFFER_SIZE = 256; }
  
  generateHash(seedA, seedB) {
    const buffer = new Uint8Array(this.BUFFER_SIZE);
    let prngX = 3 + (4 + seedA) % 32768, prngY = 12 + seedB % 32768;
    let prngZ = 17 + ((seedA & seedB) + (seedA | seedB) + seedA) % 32768;
    for (let i = 0; i < this.BUFFER_SIZE; i++) { 
      prngX = 1 + (prngX * prngY) % prngZ; 
      buffer[i] = prngX % 256; 
    }
    for (let i = 0; i < this.BUFFER_SIZE; i++) {
      buffer[i] = (buffer[i] + ((seedA >> ((i + 2) % 30)) & 1)) % 256;
      buffer[i] = (buffer[i] + ((seedB >> ((i + 7) % 30)) & 1)) % 256;
    }
    let pos = 0;
    for (let i = 0; i < 30000; i++) { 
      let t = buffer[pos]; 
      buffer[pos] = (t + i + buffer[(pos + i) % 256]) % 256; 
      pos = (t + i + pos + (t & pos)) % 256; 
    }
    let h1 = 1, h2 = 1;
    for (let i = 0; i < this.BUFFER_SIZE; i += 2) {
      h1 = ((1 + h1) * (buffer[i] + 1)) % 1073741824;
      h2 = ((1 + h2) * (buffer[i + 1] + 1)) % 1073741824;
    }
    return [h1, h2];
  }
  
  bruteForceFindPreimage(bitLength, seedA, seedB, targetHash) {
    const max = 1 << bitLength;
    for (let i = 0; i < max; i++) {
      if (this.computeMixedHash(i, seedA, seedB) === targetHash) return i;
    }
    return 0;
  }
  
  computeMixedHash(inputValue, seedA, seedB) {
    let tempL = seedA + inputValue, tempU = seedB + inputValue;
    let hash = (tempL + tempU) & 2147483647;
    for (let i = 1; i <= 16; i++) {
      hash ^= hash >> i; 
      hash >>>= 1 + (tempL & 3);
      hash = (hash * (7 + ((tempL | tempU) & 1023))) & 1073741823;
      hash += (tempU & 65535); 
      tempL >>= 1 + (hash & 1); 
      tempU >>= 1 + (tempL & 1);
    }
    return hash & 1073741823;
  }
}
// write new challenge response
function solve_challenge(bytes) {
  const r = new BitReader();
  r.init(new Uint8Array(bytes));
  
  const flag = r.readBits(1); const opcode = r.readBits(6);
  const eventType = r.readBits(3);
  const bitLength = r.readBits(5);
  const seedA = r.readBits(30);
  const seedB = r.readBits(30);
  const targetHash = r.readBits(30);
  
  console.log(`[c] bitLength: ${bitLength}`);
  console.log(`[c] seedA: 0x${seedA.toString(16).padStart(8, '0')} (${seedA})`);
  console.log(`[c] seedB: 0x${seedB.toString(16).padStart(8, '0')} (${seedB})`);
  console.log(`[c] targetHash: 0x${targetHash.toString(16).padStart(8, '0')} (${targetHash})`);
  
  const hashGen = new HashGenerator();
  const puzzle = hashGen.generateHash(seedA, seedB);
  console.log(`[c] puzzle hex: [0x${puzzle[0].toString(16).padStart(8, '0')}, 0x${puzzle[1].toString(16).padStart(8, '0')}]`);
  
  const maxAttempts = 1 << bitLength;
  const startTime = performance.now();
  
  let solution = 0;
  let iterations = 0;
  
  for (let i = 0; i < maxAttempts; i++) {
    iterations++;
    const hash = hashGen.computeMixedHash(i, seedA, seedB);
    if (hash === targetHash) {
      solution = i;
      break;
    }
    if (iterations % 100000 === 0) {
      console.log(`[c] attempt ${iterations}: current hash = 0x${hash.toString(16).padStart(8, '0')}`);
    }
  }
  
  if (solution === 0 && iterations === maxAttempts) {
    console.log(`[c] no solution after ${iterations} attempts`);
  }
  
  const endTime = performance.now();
  console.log(`\n[c] solution: ${solution}`);
  console.log(`[c] solution hex: 0x${solution.toString(16).padStart(8, '0')}`);
  console.log(`[c] iterations: ${iterations}`);
  console.log(`[c] time: ${(endTime - startTime).toFixed(2)}ms`);
  
  const dw = new BitWriter();
  dw.allocateAndInitialize(1 + 6 + 3 + 30 + 30);
  dw.writeBits(1, 0);
  dw.writeBits(6, 30);
  dw.writeBits(3, eventType);
  dw.writeBits(30, solution);
  dw.writeBits(30, 0);
  
  return dw.buffer;
}
function encode_session(user, pass) {
    const w = new BitWriter();
    w.allocateAndInitialize(1 + 6 + 120)
    w.writeBits(1, 0);
    w.writeBits(6, 17);
    const user_six_bits = user.split('').map(encode_6_bits);
    for (const value of user_six_bits) {
      w.writeBits(6, value);
    }
    const pass_six_bits = pass.split('').map(encode_6_bits);
    for (const value of pass_six_bits) {
      w.writeBits(6, value);
    }
    return w.buffer;
}
function hexToBytes(hexInput) {
  const hex = String(hexInput);
  const bytes = [];
  for (let i = 0; i < hex.length; i += 2) {
    bytes.push(parseInt(hex.substr(i, 2), 16));
  }
  return new Uint8Array(bytes);
}
function bytesToHex(bytes) {
  return Array.from(bytes)
  .map(b => b.toString(16).padStart(2, '0'))
  .join('');
}
function send_data(ws, data) {
  ws.send(data);
  console.log(`[ˆ] ${bytesToHex(data)}`);
}
async function build_static_init() {
  const dw = new BitWriter();
  dw.allocateAndInitialize(178);
  dw.writeBits(1, 0);
  dw.writeBits(6, 13);
  dw.writeBits(14, 1758); // (build number) changes every update
  dw.writeBits(4, 0);
  dw.writeBits(7, 0);
  dw.writeBits(1, true);
  dw.writeBits(1, false);
  dw.writeBits(5, new Date().getHours() % 24);
  dw.writeBits(8, 0);
  dw.writeBits(8, 0);
  dw.writeBits(90, 000000000000000000000000);
  dw.writeBits(14, 0);
  dw.writeBits(7, Math.abs(Math.floor((900 + new Date().getTimezoneOffset() + 0.5) / 15)) & 127);
  dw.writeBits(12, 952);
  return dw.buffer;
}
async function connect_menu(init, session, new_password) {
  const ws = new WebSocket('wss://territorial.io/s52/');
  ws.on('open', () => {
    send_data(ws, init);
  });
  ws.on('message', (data) => {
    console.log(`[ˇ] ${bytesToHex(data)}`);
    const r = new BitReader();
    r.init(data);
    r.readBits(1);
    const code = r.readBits(6);
    if ( code === 9 ) {
    const result = solve_challenge(data);
      send_data(ws, result.buffer);
      send_data(ws, session);
      send_data(ws, new_password);
    }
    if ( bytesToHex(data) === "16b0") {
      console.log("[i] new password accepted by server");
      ws.close();
    }
  });
  ws.on('close', (code) => {
    console.log(`[x] [${code}] connection closed`);
  });
  ws.on('error', (e) => {
    console.log(`[x] socket error: ${e}`);
  });
}
function prompt(question) {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  return new Promise(resolve => rl.question(question, ans => { rl.close(); resolve(ans.trim()); }));
}
async function main() {
  const input_user = await prompt("account name: ");
  const input_pass = await prompt("current password: ")
  const input_pass_new = await prompt("new password: ");

  const init = await build_static_init();
  const session = await encode_session(input_user, input_pass);
  const new_password = await new password_packet(input_pass_new);

  await connect_menu(init, session, new_password);
}
main();
