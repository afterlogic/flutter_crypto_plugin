//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/bcpg/sig/SignatureTarget.java
//

#ifndef SignatureTarget_H
#define SignatureTarget_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "SignatureSubpacket.h"

@class IOSByteArray;

@interface LibOrgBouncycastleBcpgSigSignatureTarget : LibOrgBouncycastleBcpgSignatureSubpacket

#pragma mark Public

- (instancetype __nonnull)initWithBoolean:(jboolean)critical
                              withBoolean:(jboolean)isLongLength
                            withByteArray:(IOSByteArray *)data;

- (instancetype __nonnull)initWithBoolean:(jboolean)critical
                                  withInt:(jint)publicKeyAlgorithm
                                  withInt:(jint)hashAlgorithm
                            withByteArray:(IOSByteArray *)hashData;

- (jint)getHashAlgorithm;

- (IOSByteArray *)getHashData;

- (jint)getPublicKeyAlgorithm;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithInt:(jint)arg0
                          withBoolean:(jboolean)arg1
                          withBoolean:(jboolean)arg2
                        withByteArray:(IOSByteArray *)arg3 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleBcpgSigSignatureTarget)

FOUNDATION_EXPORT void LibOrgBouncycastleBcpgSigSignatureTarget_initWithBoolean_withBoolean_withByteArray_(LibOrgBouncycastleBcpgSigSignatureTarget *self, jboolean critical, jboolean isLongLength, IOSByteArray *data);

FOUNDATION_EXPORT LibOrgBouncycastleBcpgSigSignatureTarget *new_LibOrgBouncycastleBcpgSigSignatureTarget_initWithBoolean_withBoolean_withByteArray_(jboolean critical, jboolean isLongLength, IOSByteArray *data) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleBcpgSigSignatureTarget *create_LibOrgBouncycastleBcpgSigSignatureTarget_initWithBoolean_withBoolean_withByteArray_(jboolean critical, jboolean isLongLength, IOSByteArray *data);

FOUNDATION_EXPORT void LibOrgBouncycastleBcpgSigSignatureTarget_initWithBoolean_withInt_withInt_withByteArray_(LibOrgBouncycastleBcpgSigSignatureTarget *self, jboolean critical, jint publicKeyAlgorithm, jint hashAlgorithm, IOSByteArray *hashData);

FOUNDATION_EXPORT LibOrgBouncycastleBcpgSigSignatureTarget *new_LibOrgBouncycastleBcpgSigSignatureTarget_initWithBoolean_withInt_withInt_withByteArray_(jboolean critical, jint publicKeyAlgorithm, jint hashAlgorithm, IOSByteArray *hashData) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleBcpgSigSignatureTarget *create_LibOrgBouncycastleBcpgSigSignatureTarget_initWithBoolean_withInt_withInt_withByteArray_(jboolean critical, jint publicKeyAlgorithm, jint hashAlgorithm, IOSByteArray *hashData);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleBcpgSigSignatureTarget)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // SignatureTarget_H
