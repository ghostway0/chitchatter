import { randomBytes } from 'crypto'

import nacl from 'tweetnacl'
import * as naclUtil from 'tweetnacl-util'

// import { KeyPair } from './types.ts'

export enum AllowedKeyType {
  PUBLIC,
  PRIVATE,
}

type KeyPair = {
  publicKey: Uint8Array
  privateKey: Uint8Array
}

export class EncryptionService {
  public cryptoKeyStub = 'cryptoKeyStub'

  public generateKeyPair = (): KeyPair => {
    const keyPair = nacl.box.keyPair()
    return {
      publicKey: keyPair.publicKey,
      privateKey: keyPair.secretKey,
    }
  }

  public encryptString = (
    our_key: Uint8Array,
    their_key: Uint8Array,
    message: string
  ): string => {
    const nonce = randomBytes(24)
    const encryptedMessage = nacl.box(
      naclUtil.decodeUTF8(message),
      nonce,
      their_key,
      our_key
    )

    if (!encryptedMessage) {
      throw new Error('Could not encrypt message')
    }

    const concatenatedMessage = new Uint8Array(
      nonce.length + encryptedMessage.length
    )
    concatenatedMessage.set(nonce)
    concatenatedMessage.set(encryptedMessage, nonce.length)

    return naclUtil.encodeBase64(concatenatedMessage)
  }

  public decryptString = (
    our_key: Uint8Array,
    their_key: Uint8Array,
    message: string
  ): string => {
    const decodedMessage = naclUtil.decodeBase64(message)
    const nonce = decodedMessage.slice(0, 24)
    const encryptedMessage = decodedMessage.slice(24)

    const decryptedMessage = nacl.box.open(
      encryptedMessage,
      nonce,
      their_key,
      our_key
    )

    if (!decryptedMessage) {
      throw new Error('Could not decrypt message')
    }

    return naclUtil.encodeUTF8(decryptedMessage)
  }

  public stringifyCryptoKey = (key: Uint8Array) => {
    return naclUtil.encodeBase64(key)
  }

  public parseCryptoKeyString = (
    keyString: string,
    keyType: AllowedKeyType
  ): Uint8Array => {
    return naclUtil.decodeBase64(keyString)
  }

  public encodePassword = async (roomId: string, password: string) => {
    const data = naclUtil.decodeUTF8(`${roomId}_${password}`)
    const digest = nacl.hash(data)
    const encodedPassword = naclUtil.encodeBase64(digest)

    return encodedPassword
  }
}

export const encryption = new EncryptionService()
