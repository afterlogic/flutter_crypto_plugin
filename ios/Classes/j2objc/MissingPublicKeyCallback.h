//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/com/afterlogic/pgp/decryption_verification/MissingPublicKeyCallback.java
//

#ifndef MissingPublicKeyCallback_H
#define MissingPublicKeyCallback_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class JavaLangLong;
@class LibOrgBouncycastleOpenpgpPGPPublicKey;

@protocol LibComAfterlogicPgpDecryption_verificationMissingPublicKeyCallback < JavaObject >

- (LibOrgBouncycastleOpenpgpPGPPublicKey *)onMissingPublicKeyEncounteredWithJavaLangLong:(JavaLangLong *)keyId;

@end

J2OBJC_EMPTY_STATIC_INIT(LibComAfterlogicPgpDecryption_verificationMissingPublicKeyCallback)

J2OBJC_TYPE_LITERAL_HEADER(LibComAfterlogicPgpDecryption_verificationMissingPublicKeyCallback)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // MissingPublicKeyCallback_H
