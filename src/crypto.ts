import { webcrypto } from "crypto";

function arrayBufferToBase64(buffer: ArrayBuffer): string {
  return Buffer.from(buffer).toString("base64");
}

function base64ToArrayBuffer(base64: string): ArrayBuffer {
  var buff = Buffer.from(base64, "base64");
  return buff.buffer.slice(buff.byteOffset, buff.byteOffset + buff.byteLength) as ArrayBuffer;
}

type GenerateRsaKeyPair = {
  publicKey: webcrypto.CryptoKey;
  privateKey: webcrypto.CryptoKey;
};
export async function generateRsaKeyPair(): Promise<GenerateRsaKeyPair> {
  const keyPair = await webcrypto.subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    true,
    ["encrypt", "decrypt"]
  );

  return {
    publicKey: keyPair.publicKey,
    privateKey: keyPair.privateKey,
  };
}

export async function exportPubKey(key: webcrypto.CryptoKey): Promise<string> {
  const exportedKey = await webcrypto.subtle.exportKey("spki", key);
  return arrayBufferToBase64(exportedKey);
}

export async function exportPrvKey(
  key: webcrypto.CryptoKey | null
): Promise<string | null> {
  if (!key) return null;
  const exportedKey = await webcrypto.subtle.exportKey("pkcs8", key);
  return arrayBufferToBase64(exportedKey);
}

export async function importPubKey(
  strKey: string
): Promise<webcrypto.CryptoKey> {
  const arrayBuffer = base64ToArrayBuffer(strKey);
  return webcrypto.subtle.importKey(
    "spki",
    arrayBuffer,
    {
      name: "RSA-OAEP",
      hash: "SHA-256",
    },
    true,
    ["encrypt"]
  );
}

export async function importPrvKey(
  strKey: string
): Promise<webcrypto.CryptoKey> {
  const arrayBuffer = base64ToArrayBuffer(strKey);
  return webcrypto.subtle.importKey(
    "pkcs8",
    arrayBuffer,
    {
      name: "RSA-OAEP",
      hash: "SHA-256",
    },
    true,
    ["decrypt"]
  );
}

export async function rsaEncrypt(
  b64Data: string,
  strPublicKey: string
): Promise<string> {
  const publicKey = await importPubKey(strPublicKey);
  const data = base64ToArrayBuffer(b64Data);
  const encryptedData = await webcrypto.subtle.encrypt(
    {
      name: "RSA-OAEP",
    },
    publicKey,
    data
  );
  return arrayBufferToBase64(encryptedData);
}

export async function rsaDecrypt(
  data: string,
  privateKey: webcrypto.CryptoKey
): Promise<string> {
  const encryptedData = base64ToArrayBuffer(data);
  const decryptedData = await webcrypto.subtle.decrypt(
    {
      name: "RSA-OAEP",
    },
    privateKey,
    encryptedData
  );
  return arrayBufferToBase64(decryptedData);
}

export async function createRandomSymmetricKey(): Promise<webcrypto.CryptoKey> {
  return webcrypto.subtle.generateKey(
    {
      name: "AES-CBC",
      length: 256,
    },
    true,
    ["encrypt", "decrypt"]
  );
}

export async function exportSymKey(key: webcrypto.CryptoKey): Promise<string> {
  const exportedKey = await webcrypto.subtle.exportKey("raw", key);
  return arrayBufferToBase64(exportedKey);
}

export async function importSymKey(
  strKey: string
): Promise<webcrypto.CryptoKey> {
  const arrayBuffer = base64ToArrayBuffer(strKey);
  return webcrypto.subtle.importKey(
    "raw",
    arrayBuffer,
    {
      name: "AES-CBC",
    },
    true,
    ["encrypt", "decrypt"]
  );
}

export async function symEncrypt(
  key: webcrypto.CryptoKey,
  data: string
): Promise<string> {
  const iv = webcrypto.getRandomValues(new Uint8Array(16));
  const encodedData = new TextEncoder().encode(data);
  const encryptedData = await webcrypto.subtle.encrypt(
    {
      name: "AES-CBC",
      iv: iv,
    },
    key,
    encodedData
  );
  const combined = new Uint8Array(iv.length + encryptedData.byteLength);
  combined.set(new Uint8Array(iv), 0);
  combined.set(new Uint8Array(encryptedData), iv.length);
  return arrayBufferToBase64(combined.buffer);
}

export async function symDecrypt(
  strKey: string,
  encryptedData: string
): Promise<string> {
  const key = await importSymKey(strKey);
  const arrayBuffer = base64ToArrayBuffer(encryptedData);
  const iv = arrayBuffer.slice(0, 16);
  const data = arrayBuffer.slice(16);
  const decryptedData = await webcrypto.subtle.decrypt(
    {
      name: "AES-CBC",
      iv: iv,
    },
    key,
    data
  );
  return new TextDecoder().decode(decryptedData);
}
