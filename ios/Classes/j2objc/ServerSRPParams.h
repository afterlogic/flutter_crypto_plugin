//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/tls/ServerSRPParams.java
//

#ifndef ServerSRPParams_H
#define ServerSRPParams_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class IOSByteArray;
@class JavaIoInputStream;
@class JavaIoOutputStream;
@class JavaMathBigInteger;

@interface LibOrgBouncycastleCryptoTlsServerSRPParams : NSObject {
 @public
  JavaMathBigInteger *N_;
  JavaMathBigInteger *g_;
  JavaMathBigInteger *B_;
  IOSByteArray *s_;
}

#pragma mark Public

- (instancetype __nonnull)initWithJavaMathBigInteger:(JavaMathBigInteger *)N
                              withJavaMathBigInteger:(JavaMathBigInteger *)g
                                       withByteArray:(IOSByteArray *)s
                              withJavaMathBigInteger:(JavaMathBigInteger *)B;

- (void)encodeWithJavaIoOutputStream:(JavaIoOutputStream *)output;

- (JavaMathBigInteger *)getB;

- (JavaMathBigInteger *)getG;

- (JavaMathBigInteger *)getN;

- (IOSByteArray *)getS;

+ (LibOrgBouncycastleCryptoTlsServerSRPParams *)parseWithJavaIoInputStream:(JavaIoInputStream *)input;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleCryptoTlsServerSRPParams)

J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoTlsServerSRPParams, N_, JavaMathBigInteger *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoTlsServerSRPParams, g_, JavaMathBigInteger *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoTlsServerSRPParams, B_, JavaMathBigInteger *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoTlsServerSRPParams, s_, IOSByteArray *)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoTlsServerSRPParams_initWithJavaMathBigInteger_withJavaMathBigInteger_withByteArray_withJavaMathBigInteger_(LibOrgBouncycastleCryptoTlsServerSRPParams *self, JavaMathBigInteger *N, JavaMathBigInteger *g, IOSByteArray *s, JavaMathBigInteger *B);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoTlsServerSRPParams *new_LibOrgBouncycastleCryptoTlsServerSRPParams_initWithJavaMathBigInteger_withJavaMathBigInteger_withByteArray_withJavaMathBigInteger_(JavaMathBigInteger *N, JavaMathBigInteger *g, IOSByteArray *s, JavaMathBigInteger *B) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoTlsServerSRPParams *create_LibOrgBouncycastleCryptoTlsServerSRPParams_initWithJavaMathBigInteger_withJavaMathBigInteger_withByteArray_withJavaMathBigInteger_(JavaMathBigInteger *N, JavaMathBigInteger *g, IOSByteArray *s, JavaMathBigInteger *B);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoTlsServerSRPParams *LibOrgBouncycastleCryptoTlsServerSRPParams_parseWithJavaIoInputStream_(JavaIoInputStream *input);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoTlsServerSRPParams)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // ServerSRPParams_H