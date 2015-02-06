//
//  YYDes.m
//  YYDes
//
//  Created by hanyazhou on 15/2/6.
//  Copyright (c) 2015年 HYZ. All rights reserved.
//

#import "YYDes.h"

@implementation YYDes
/******************************************************************************
 函数名称 : + (NSData *)DESEncrypt:(NSData *)data WithKey:(NSString *)key
 函数描述 : 文本数据进行DES加密
 输入参数 : (NSData *)data
 (NSString *)key
 输出参数 : N/A
 返回参数 : (NSData *)
 备注信息 : 此函数不可用于过长文本
 ******************************************************************************/
+ (NSString *)DESEncrypt:(NSData *)data WithKey:(NSString *)key
{
    
    Byte iv[] = {1,3,7,3,3,8,2,7};
    char keyPtr[kCCKeySizeAES256+1];
    bzero(keyPtr, sizeof(keyPtr));
    
    [key getCString:keyPtr maxLength:sizeof(keyPtr) encoding:NSUTF8StringEncoding];
    
    NSUInteger dataLength = [data length];
    
    size_t bufferSize = dataLength + kCCBlockSizeAES128;
    void *buffer = malloc(bufferSize);
    
    size_t numBytesEncrypted = 0;
    CCCryptorStatus cryptStatus = CCCrypt(kCCEncrypt, kCCAlgorithmDES,
                                          kCCOptionPKCS7Padding ,
                                          keyPtr, kCCBlockSizeDES,
                                          iv,
                                          [data bytes], dataLength,
                                          buffer, bufferSize,
                                          &numBytesEncrypted);
    if (cryptStatus == kCCSuccess) {
        return [GTMBase64 stringByEncodingData:[NSData dataWithBytesNoCopy:buffer length:numBytesEncrypted]];
    }
    
    free(buffer);
    return nil;
}

/******************************************************************************
 函数名称 : + (NSData *)DESEncrypt:(NSData *)data WithKey:(NSString *)key
 函数描述 : 文本数据进行DES解密
 输入参数 : (NSData *)data
 (NSString *)key
 输出参数 : N/A
 返回参数 : (NSData *)
 备注信息 : 此函数不可用于过长文本
 ******************************************************************************/
+ (NSData *)DESDecrypt:(NSData *)data WithKey:(NSString *)key
{
    Byte iv[] = {1,3,7,3,3,8,2,7};
    
    char keyPtr[kCCKeySizeAES256+1];
    bzero(keyPtr, sizeof(keyPtr));
    
    [key getCString:keyPtr maxLength:sizeof(keyPtr) encoding:NSUTF8StringEncoding];
    
    NSUInteger dataLength = [data length];
    
    size_t bufferSize = dataLength + kCCBlockSizeAES128;
    void *buffer = malloc(bufferSize);
    
    size_t numBytesDecrypted = 0;
    CCCryptorStatus cryptStatus = CCCrypt(kCCDecrypt, kCCAlgorithmDES,
                                          kCCOptionPKCS7Padding,
                                          keyPtr, kCCBlockSizeDES,
                                          iv,
                                          [data bytes], dataLength,
                                          buffer, bufferSize,
                                          &numBytesDecrypted);
    
    if (cryptStatus == kCCSuccess) {
        return [NSData dataWithBytesNoCopy:buffer length:numBytesDecrypted];
    }
    
    free(buffer);
    return nil;
}

+ (NSString *)DESDecryptString:(NSString *)desString WithKey:(NSString *)key{
    NSData *desData = [GTMBase64 decodeString:desString];
    return [[NSString alloc] initWithData:[self DESDecrypt:desData WithKey:key] encoding:NSUTF8StringEncoding];
}

+ (NSString*)SHA1:(NSString *)string
{
    const char *cstr = [string cStringUsingEncoding:NSUTF8StringEncoding];
    NSData *data = [NSData dataWithBytes:cstr length:string.length];
    
    uint8_t digest[CC_SHA1_DIGEST_LENGTH];
    
    CC_SHA1(data.bytes, (uint32_t)data.length, digest);
    
    NSMutableString* output = [NSMutableString stringWithCapacity:CC_SHA1_DIGEST_LENGTH * 2];
    
    for(int i = 0; i < CC_SHA1_DIGEST_LENGTH; i++)
        [output appendFormat:@"%02x", digest[i]];
    
    return output;
}

+ (NSString *)generate:(NSDictionary *)parameters {
    NSArray *keysArray = [[parameters allKeys] sortedArrayUsingSelector:@selector(compare:)];
    NSString *parametersString = [NSString string];
    for (NSString *string in keysArray) {
        parametersString =[parametersString stringByAppendingString:[NSString stringWithFormat:@"%@%@",string,parameters[string]]];
    }
    return [[self SHA1:[NSString stringWithFormat:@"abcdeabcdeabcdeabcdeabcde%@abcdeabcdeabcdeabcdeabcde",parametersString]] uppercaseString];
}

/*
 + (NSString *) hmacSha1:(NSString*)key text:(NSString*)text	{
 const char *cKey  = [key cStringUsingEncoding:NSUTF8StringEncoding];
 const char *cData = [text cStringUsingEncoding:NSUTF8StringEncoding];
 
 uint8_t cHMAC[CC_SHA1_DIGEST_LENGTH];
 
 CCHmac(kCCHmacAlgSHA1, cKey, strlen(cKey), cData, strlen(cData), cHMAC);
 
 //NSData *HMAC = [[NSData alloc] initWithBytes:cHMAC length:CC_SHA1_DIGEST_LENGTH];
 NSString *hash;
 NSMutableString* output = [NSMutableString stringWithCapacity:CC_SHA1_DIGEST_LENGTH * 2];
 for(int i = 0; i < CC_SHA1_DIGEST_LENGTH; i++)
 [output appendFormat:@"%02x", cHMAC[i]];
 hash = output;
 
 return hash;
 }
 */

/*
 - (NSString *)md5HexDigest:(NSString*)password
 {
 const char *original_str = [password UTF8String];
 unsigned char result[CC_MD5_DIGEST_LENGTH];
 CC_MD5(original_str, strlen(original_str), result);
 NSMutableString *hash = [NSMutableString string];
 for (int i = 0; i < 16; i++)
 {
 [hash appendFormat:@"%02X", result[i]];
 }
 NSString *mdfiveString = [hash lowercaseString];
 return mdfiveString;
 }
 */

@end
