//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/KeyEncapsulation.java
//

#ifndef KeyEncapsulation_H
#define KeyEncapsulation_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class IOSByteArray;
@protocol LibOrgBouncycastleCryptoCipherParameters;

@protocol LibOrgBouncycastleCryptoKeyEncapsulation < JavaObject >

- (void)init__WithLibOrgBouncycastleCryptoCipherParameters:(id<LibOrgBouncycastleCryptoCipherParameters>)param OBJC_METHOD_FAMILY_NONE;

- (id<LibOrgBouncycastleCryptoCipherParameters>)encryptWithByteArray:(IOSByteArray *)outArg
                                                             withInt:(jint)outOff
                                                             withInt:(jint)keyLen;

- (id<LibOrgBouncycastleCryptoCipherParameters>)decryptWithByteArray:(IOSByteArray *)inArg
                                                             withInt:(jint)inOff
                                                             withInt:(jint)inLen
                                                             withInt:(jint)keyLen;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleCryptoKeyEncapsulation)

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoKeyEncapsulation)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // KeyEncapsulation_H
