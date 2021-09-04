#import <React/RCTBridgeModule.h>

@interface RCT_EXTERN_MODULE(Pbkdf2, NSObject)
//derive:withSalt:withIterations:withHash:withKeyLength:withResolver:withRejecter:
RCT_EXTERN_METHOD(derive:(NSString)password
                  withSalt:(NSData)salt
                  withIterations:(NSNumber)iterations
                  withHash:(NSString)hash
                  withKeyLength:(NSNumber)keyLength
                  withResolver:(RCTPromiseResolveBlock)resolve
                  withRejecter:(RCTPromiseRejectBlock)reject)

@end
