//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/engines/VMPCKSA3Engine.java
//

#ifndef VMPCKSA3Engine_H
#define VMPCKSA3Engine_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "VMPCEngine.h"

@class IOSByteArray;

@interface LibOrgBouncycastleCryptoEnginesVMPCKSA3Engine : LibOrgBouncycastleCryptoEnginesVMPCEngine

#pragma mark Public

- (instancetype __nonnull)init;

- (NSString *)getAlgorithmName;

#pragma mark Protected

- (void)initKeyWithByteArray:(IOSByteArray *)keyBytes
               withByteArray:(IOSByteArray *)ivBytes OBJC_METHOD_FAMILY_NONE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleCryptoEnginesVMPCKSA3Engine)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoEnginesVMPCKSA3Engine_init(LibOrgBouncycastleCryptoEnginesVMPCKSA3Engine *self);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoEnginesVMPCKSA3Engine *new_LibOrgBouncycastleCryptoEnginesVMPCKSA3Engine_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoEnginesVMPCKSA3Engine *create_LibOrgBouncycastleCryptoEnginesVMPCKSA3Engine_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoEnginesVMPCKSA3Engine)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // VMPCKSA3Engine_H