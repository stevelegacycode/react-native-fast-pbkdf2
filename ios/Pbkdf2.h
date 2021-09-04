#import <Foundation/Foundation.h>
#import <React/RCTBridgeModule.h>

@interface Pbkdf2 : NSObject <RCTBridgeModule>

@end

@interface NSData (NSData_Conversion)

#pragma mark - String Conversion
- (NSString *)hexadecimalString;

@end
