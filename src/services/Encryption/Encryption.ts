import * as sodium from 'libsodium-wrappers'

export enum AllowedKeyType {
  PUBLIC,
  PRIVATE,
}

const arrayBufferToBase64 = (buffer: ArrayBuffer) => {
  const binary = String.fromCharCode(...new Uint8Array(buffer))
  return btoa(binary)
}

const base64ToArrayBuffer = (base64: string) => {
  const binaryString = atob(base64)
  const bytes = new Uint8Array(binaryString.length)
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i)
  }
  return bytes.buffer
}

export class EncryptionService {
  cryptoKeyStub: CryptoKey = {
    algorithm: { name: 'STUB-ALGORITHM' },
    extractable: false,
    type: 'private',
    usages: [],
  }

  async init() {
    await sodium.ready
  }

  generateKeyPair = async (): Promise<CryptoKeyPair> => {
    const keyPair = sodium.crypto_kx_keypair()
    return {
      publicKey: keyPair.publicKey.buffer as CryptoKey,
      privateKey: keyPair.privateKey.buffer as CryptoKey,
    }
  }

  encodePassword = async (roomId: string, password: string) => {
    const data = new TextEncoder().encode(`${roomId}_${password}`)
    const hash = sodium.crypto_generichash(32, data)
    return arrayBufferToBase64(hash.buffer)
  }

  stringifyCryptoKey = async (cryptoKey: CryptoKey) => {
    const keyData = cryptoKey as ArrayBuffer
    return arrayBufferToBase64(keyData)
  }

  parseCryptoKeyString = async (keyString: string, type: AllowedKeyType) => {
    const keyArray = base64ToArrayBuffer(keyString)
    return type === AllowedKeyType.PUBLIC
      ? { publicKey: keyArray as CryptoKey }
      : { privateKey: keyArray as CryptoKey }
  }

  encryptString = async (publicKey: CryptoKey, plaintext: string) => {
    const nonce = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES)
    const key = new Uint8Array(publicKey as ArrayBuffer)
    const message = new TextEncoder().encode(plaintext)
    const encryptedData = sodium.crypto_secretbox_easy(message, nonce, key)
    return encryptedData.buffer
  }

  decryptString = async (privateKey: CryptoKey, encryptedData: ArrayBuffer) => {
    const nonce = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES)
    const key = new Uint8Array(privateKey as ArrayBuffer)
    const decryptedData = sodium.crypto_secretbox_open_easy(
      new Uint8Array(encryptedData),
      nonce,
      key
    )
    return new TextDecoder().decode(decryptedData)
  }
}

export const encryption = new EncryptionService()
