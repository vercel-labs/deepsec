import type { CandidateMatch } from "@deepsec/core";
import type { MatcherPlugin } from "../types.js";

/**
 * Wide-net matcher: any file that touches cryptographic primitives (sign,
 * verify, encrypt, decrypt, hash, HMAC, random, key derivation, TLS, JWT).
 * Paired with the AI pass this surfaces the specific subtle bugs the narrow
 * `insecure-crypto` matcher can't catch — algorithm confusion, missing
 * constant-time comparisons, IV reuse, timing-unsafe checks, weak key sizes,
 * incorrect tag verification order, and replay protection gaps.
 *
 * Scoped to Go, TS/JS, and Python. Skips tests (they exercise crypto legitimately).
 */

// Multi-language import patterns
const IMPORT_PATTERNS: { regex: RegExp; label: string }[] = [
  // Go standard library crypto/*
  {
    regex:
      /"crypto\/(?:aes|cipher|des|dsa|ecdh|ecdsa|ed25519|elliptic|hmac|md5|rand|rc4|rsa|sha1|sha256|sha512|subtle|x509|tls)"/,
    label: "Go crypto/* import",
  },
  { regex: /"golang\.org\/x\/crypto\//, label: "Go golang.org/x/crypto import" },
  // Node / JS crypto libraries
  { regex: /(?:require|from)\s*\(?\s*['"](?:node:)?crypto['"]/, label: "Node crypto import" },
  {
    regex:
      /(?:require|from)\s*\(?\s*['"](?:crypto-js|tweetnacl|@noble\/[\w-]+|jose|jsonwebtoken|bcrypt|bcryptjs|argon2|scrypt|tweetsodium|libsodium-wrappers|node-forge|elliptic|sjcl)['"]/,
    label: "JS crypto library import",
  },
  { regex: /crypto\.subtle\.\w+/, label: "Web Crypto API (crypto.subtle.*)" },
  // Python
  {
    regex:
      /^\s*(?:from|import)\s+(?:cryptography|hashlib|hmac|secrets|Crypto|nacl|jwt|passlib|bcrypt|argon2|pycryptodome)\b/m,
    label: "Python crypto import",
  },
];

// Call-site patterns (language-agnostic shapes)
const CALL_PATTERNS: { regex: RegExp; label: string }[] = [
  // Go
  { regex: /\bed25519\.(Sign|Verify|GenerateKey|NewKeyFromSeed)\s*\(/, label: "Go ed25519 op" },
  { regex: /\brsa\.(Encrypt|Decrypt|Sign|Verify)\w*\s*\(/, label: "Go RSA op" },
  { regex: /\becdsa\.(Sign|Verify|GenerateKey)\w*\s*\(/, label: "Go ECDSA op" },
  { regex: /\bhmac\.(New|Equal)\s*\(/, label: "Go HMAC op" },
  { regex: /\baes\.NewCipher\s*\(/, label: "Go AES init" },
  {
    regex: /\bcipher\.New(?:GCM|CBCEncrypter|CBCDecrypter|CFBEncrypter|CFBDecrypter|CTR|OFB)\s*\(/,
    label: "Go cipher mode",
  },
  {
    regex: /\bsubtle\.ConstantTime(?:Compare|Eq|Select|ByteEq|Copy|LessOrEq)\s*\(/,
    label: "Go subtle compare",
  },
  { regex: /\bx509\.(Parse|Create|Verify)\w*\s*\(/, label: "Go x509 op" },
  { regex: /\btls\.(Config|Certificate|Dial|Listen|Server|Client)\s*[({]/, label: "Go TLS op" },
  { regex: /\b(?:sha256|sha512|sha1|md5)\.(?:New|Sum\d*)\s*\(/, label: "Go hash op" },
  // Node / JS
  {
    regex:
      /\bcreate(?:Hash|Hmac|Cipher(?:iv)?|Decipher(?:iv)?|Sign|Verify|PrivateKey|PublicKey|SecretKey|DiffieHellman|ECDH)\s*\(/,
    label: "Node crypto.create*",
  },
  { regex: /\brandomBytes\s*\(/, label: "Node randomBytes" },
  { regex: /\brandomUUID\s*\(/, label: "Node randomUUID" },
  { regex: /\bpbkdf2(?:Sync)?\s*\(/, label: "Node pbkdf2" },
  { regex: /\bscrypt(?:Sync)?\s*\(/, label: "Node scrypt" },
  { regex: /\btimingSafeEqual\s*\(/, label: "Node timingSafeEqual" },
  {
    regex: /\bcrypto\.(?:sign|verify|hkdf|generateKeyPair(?:Sync)?|diffieHellman)\s*\(/,
    label: "Node crypto op",
  },
  { regex: /\bjwt\.(sign|verify|decode)\s*\(/, label: "JWT sign/verify" },
  {
    regex:
      /\bjose\.(SignJWT|jwtVerify|importJWK|importSPKI|importPKCS8|compactSign|compactVerify|flattenedSign|flattenedVerify|generalSign|generalVerify|EncryptJWT|jwtDecrypt|EncryptSHE|compactDecrypt|flattenedDecrypt|generalDecrypt|CompactEncrypt|FlattenedEncrypt|GeneralEncrypt)\b/,
    label: "jose lib",
  },
  // Web Crypto
  {
    regex:
      /\bcrypto\.subtle\.(encrypt|decrypt|sign|verify|digest|generateKey|deriveKey|deriveBits|importKey|exportKey|wrapKey|unwrapKey)\s*\(/,
    label: "Web Crypto subtle.*",
  },
  // Python
  {
    regex: /\bhashlib\.(?:md5|sha1|sha224|sha256|sha384|sha512|blake2\w*|pbkdf2_hmac)\s*\(/,
    label: "Python hashlib",
  },
  { regex: /\bhmac\.(?:new|compare_digest|HMAC)\s*\(/, label: "Python hmac" },
  {
    regex:
      /\bsecrets\.(token_bytes|token_hex|token_urlsafe|randbelow|choice|compare_digest|SystemRandom)\s*\(/,
    label: "Python secrets",
  },
];

const ALL_PATTERNS = [...IMPORT_PATTERNS, ...CALL_PATTERNS];

export const cryptoUsageMatcher: MatcherPlugin = {
  noiseTier: "normal" as const,
  slug: "crypto-usage",
  description:
    "Any file that uses cryptographic primitives (sign/verify/encrypt/hash/HMAC/random/key-derivation) — wide net for AI review",
  filePatterns: ["**/*.go", "**/*.{ts,tsx,js,jsx,mjs,cjs}", "**/*.py"],
  examples: [
    `import "crypto/aes"`,
    `import "crypto/sha256"`,
    `import "golang.org/x/crypto/bcrypt"`,
    `const crypto = require('node:crypto');`,
    `import jwt from "jsonwebtoken";`,
    `import { SignJWT } from "jose";`,
    `const hash = crypto.subtle.digest("SHA-256", data);`,
    `from cryptography.hazmat.primitives import hashes`,
    `import hashlib`,
    `sig := ed25519.Sign(priv, msg)`,
    `cipher := rsa.EncryptPKCS1v15(rand, pub, msg)`,
    `r, s, err := ecdsa.Sign(rand, key, hash)`,
    `mac := hmac.New(sha256.New, key)`,
    `block, _ := aes.NewCipher(key)`,
    `gcm, _ := cipher.NewGCM(block)`,
    `if subtle.ConstantTimeCompare(a, b) == 1 { }`,
    `cert, _ := x509.ParseCertificate(der)`,
    `tls.Config{ MinVersion: tls.VersionTLS12 }`,
    `h := sha256.New()`,
    `const hash = createHash('sha256');`,
    `const buf = randomBytes(32);`,
    `const id = randomUUID();`,
    `const key = pbkdf2Sync(password, salt, 100000, 64, 'sha512');`,
    `scrypt(password, salt, 64, (err, key) => {});`,
    `if (timingSafeEqual(a, b)) ok();`,
    `const sig = jwt.sign({ id: 1 }, secret);`,
    `const out = await jose.jwtVerify(token, key);`,
    `await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, data);`,
    `import hmac
mac = hmac.new(key, msg, hashlib.sha256)`,
    `import secrets
token = secrets.token_hex(16)`,
    `import hashlib
h = hashlib.sha256(b"abc")`,
  ],
  match(content, filePath) {
    if (/_test\.go$/.test(filePath)) return [];
    if (/\.(test|spec)\.(ts|tsx|js|jsx|mjs|cjs)$/.test(filePath)) return [];
    if (/(?:^|\/)__tests__\//.test(filePath)) return [];
    if (/\.d\.ts$/.test(filePath)) return [];
    if (/(?:^|\/)gen\//.test(filePath)) return [];

    const lines = content.split("\n");
    const hitLines: number[] = [];
    const labels = new Set<string>();
    let firstContext: string | undefined;

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      for (const { regex, label } of ALL_PATTERNS) {
        if (regex.test(line)) {
          hitLines.push(i + 1);
          labels.add(label);
          if (firstContext === undefined) {
            const s = Math.max(0, i - 2);
            const e = Math.min(lines.length, i + 3);
            firstContext = lines.slice(s, e).join("\n");
          }
          break; // one label per line is enough
        }
      }
    }

    if (hitLines.length === 0) return [];
    const match: CandidateMatch = {
      vulnSlug: "crypto-usage",
      lineNumbers: hitLines,
      snippet: firstContext ?? "",
      matchedPattern: Array.from(labels).slice(0, 5).join(", "),
    };
    return [match];
  },
};
