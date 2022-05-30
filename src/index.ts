import { NativeModules } from 'react-native';

const implementation = {
  derive(password: string | Buffer, salt: string | Buffer, iterations: number, keySize: number, hash: 'sha-1' | 'sha-256' | 'sha-512'): Promise<string | Buffer> {
    const isBufferPassword = Buffer.isBuffer(password)
    const isBufferSalt = Buffer.isBuffer(salt)
    const returnBuffer = isBufferPassword || isBufferSalt
    const sPassword = isBufferPassword ? password.toString('base64') : password
    const sSalt = isBufferSalt ? salt.toString('base64') : salt
    return NativeModules.Pbkdf2.derive(sPassword, sSalt, iterations, keySize, hash)
      .then(result => returnBuffer ? Buffer.from(result) : result);
  },
  deriveSync(password: string | Buffer, salt: string | Buffer, iterations: number, keySize: number, hash: 'sha-1' | 'sha-256' | 'sha-512'): string | Buffer {

    const isBufferPassword = Buffer.isBuffer(password)
    const isBufferSalt = Buffer.isBuffer(salt)
    const returnBuffer = isBufferPassword || isBufferSalt
    const sPassword = isBufferPassword ? password.toString('base64') : password
    const sSalt = isBufferSalt ? salt.toString('base64') : salt

    // When debugger onpend, you can't use synchronous native function
    // https://github.com/facebook/react-native/issues/26705
    // check debugger is running
    // https://stackoverflow.com/a/50377644/12639496
    const haveRemoteDev = (typeof global.DedicatedWorkerGlobalScope) !== 'undefined';
    if (haveRemoteDev) {
      const pbkdf2Sync = require('../../pbkdf2').pbkdf2Sync
      if (!pbkdf2Sync) throw Error('There\' no pbkdf2')
      return pbkdf2Sync(sPassword, sSalt, iterations, keySize, hash);
    }

    const result = NativeModules.Pbkdf2.deriveSync(sPassword, sSalt, iterations, keySize, hash);
    return returnBuffer ? Buffer.from(result) : result
  },
};

export default implementation;