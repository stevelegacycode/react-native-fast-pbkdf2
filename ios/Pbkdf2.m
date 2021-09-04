#import "Pbkdf2.h"
#import <CommonCrypto/CommonCrypto.h>

@implementation NSData (NSData_Conversion)

#pragma mark - String Conversion
- (NSString *)hexadecimalString {
    /* Returns hexadecimal string of NSData. Empty string if data is empty.   */

    const unsigned char *dataBuffer = (const unsigned char *)[self bytes];

    if (!dataBuffer)
        return [NSString string];

    NSUInteger          dataLength  = [self length];
    NSMutableString     *hexString  = [NSMutableString stringWithCapacity:(dataLength * 2)];

    for (int i = 0; i < dataLength; ++i)
        [hexString appendString:[NSString stringWithFormat:@"%02lx", (unsigned long)dataBuffer[i]]];

    return [NSString stringWithString:hexString];
}

@end

@implementation Pbkdf2

RCT_EXPORT_MODULE()

// Example method
// See // https://reactnative.dev/docs/native-modules-ios
RCT_REMAP_METHOD(derive,
                 withPassword:(nonnull NSData*)password
                 withSalt:(nonnull NSData*)salt
                 withRounds:(nonnull NSNumber*)rounds
                 withKeyLength:(nonnull NSNumber*)keyLength
                 withHash:(nonnull NSString*)hash
                 withResolver:(RCTPromiseResolveBlock)resolve
                 withRejecter:(RCTPromiseRejectBlock)reject)
{
    NSMutableData *derivedKey = [NSMutableData dataWithLength: [keyLength unsignedIntValue]];
    
    
    CCPseudoRandomAlgorithm prf = kCCPRFHmacAlgSHA1;
    if ([hash isEqualToString:@"sha-512"]) {
        prf = kCCPRFHmacAlgSHA512;
    }
    if ([hash isEqualToString:@"sha-256"]) {
        prf = kCCPRFHmacAlgSHA256;
    }

    CCKeyDerivationPBKDF(kCCPBKDF2,               // algorithm
                         password.bytes,           // password
                         password.length,          // passwordLength
                         salt.bytes,              // salt
                         salt.length,             // saltLen
                         prf,       // PRF
                         [rounds unsignedIntValue],                  // rounds
                         derivedKey.mutableBytes, // derivedKey
                         derivedKey.length);      // derivedKeyLen

    resolve([derivedKey hexadecimalString]);
}

@end
