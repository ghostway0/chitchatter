import { vi } from 'vitest'
import { encryption } from 'services/Encryption'

export const mockEncryptionService = encryption

mockEncryptionService.generateKeyPair = vi.fn(() => ({
  publicKey: encryption.cryptoKeyStub,
  privateKey: encryption.cryptoKeyStub,
}))

mockEncryptionService.encodePassword = async () => ''

mockEncryptionService.stringifyCryptoKey = async () => ''

mockEncryptionService.parseCryptoKeyString = async () =>
  encryption.cryptoKeyStub
