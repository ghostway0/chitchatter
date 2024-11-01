import { encryption } from 'services/Encryption'

describe('Encryption', () => {
  it('should have a cryptoKeyStub property', () => {
    expect(encryption.cryptoKeyStub).toBeDefined()
  })

  it('should have a generateKeyPair method', () => {
    expect(encryption.generateKeyPair).toBeDefined()
  })

  it('should have an encodePassword method', () => {
    expect(encryption.encodePassword).toBeDefined()
  })

  it('should have a stringifyCryptoKey method', () => {
    expect(encryption.stringifyCryptoKey).toBeDefined()
  })

  it('should have a parseCryptoKeyString method', () => {
    expect(encryption.parseCryptoKeyString).toBeDefined()
  })

  it('should have an encryptString method', () => {
    expect(encryption.encryptString).toBeDefined()
  })
})
