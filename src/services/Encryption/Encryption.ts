import * as sodium from 'libsodium-wrappers'

export enum AllowedKeyType {
  PUBLIC,
  PRIVATE,
}

type KeyPair = {
  publicKey: Uint8Array
  privateKey: Uint8Array
}

export class EncryptionService {
  private keyPair: sodium.KeyPair | null = null

  async initialize() {
    await sodium.ready
  }

  generateKeyPair = async (): Promise<KeyPair> => {
    await this.initialize()
    this.keyPair = sodium.crypto_kx_keypair()
    console.log(this.keyPair.publicKey)
    console.log(this.keyPair.privateKey)
    return {
      publicKey: this.keyPair.publicKey,
      privateKey: this.keyPair.privateKey,
    }
  }

  encodePassword = async (roomId: string, password: string) => {
    const data = new TextEncoder().encode(`${roomId}_${password}`)
    const digest = sodium.crypto_generichash(32, data)
    return sodium.to_base64(digest)
  }

  stringifyCryptoKey = (cryptoKey: Uint8Array) => {
    return sodium.to_base64(cryptoKey)
  }

  parseCryptoKeyString = (keyString: string) => {
    return sodium.from_base64(keyString)
  }

  encryptString = async (publicKey: Uint8Array, plaintext: string) => {
    await this.initialize()
    const nonce = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES)
    const key = sodium.crypto_generichash(32, publicKey)
    const message = new TextEncoder().encode(plaintext)
    console.log(message, publicKey, key)
    const encryptedData = sodium.crypto_secretbox_easy(message, nonce, key)
    return { encryptedData, nonce }
  }

  decryptString = async (
    privateKey: Uint8Array,
    encryptedDataBase64: string,
    nonceBase64: string
  ) => {
    await this.sodiumReady

    const encryptedData = sodium.from_base64(encryptedDataBase64)
    const nonce = sodium.from_base64(nonceBase64)

    const key = sodium.crypto_generichash(32, privateKey)

    const decrypted = sodium.crypto_secretbox_open_easy(
      encryptedData,
      nonce,
      key
    )

    if (!decrypted) throw new Error('Decryption failed')
    return new TextDecoder().decode(decrypted)
  }
}

export const encryption = new EncryptionService()
