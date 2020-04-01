//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/util/SubjectPublicKeyInfoFactory.java
//

#ifndef SubjectPublicKeyInfoFactory_H
#define SubjectPublicKeyInfoFactory_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class LibOrgBouncycastleAsn1X509SubjectPublicKeyInfo;
@class LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter;

@interface LibOrgBouncycastleCryptoUtilSubjectPublicKeyInfoFactory : NSObject

#pragma mark Public

+ (LibOrgBouncycastleAsn1X509SubjectPublicKeyInfo *)createSubjectPublicKeyInfoWithLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter:(LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *)publicKey;

@end

J2OBJC_STATIC_INIT(LibOrgBouncycastleCryptoUtilSubjectPublicKeyInfoFactory)

FOUNDATION_EXPORT LibOrgBouncycastleAsn1X509SubjectPublicKeyInfo *LibOrgBouncycastleCryptoUtilSubjectPublicKeyInfoFactory_createSubjectPublicKeyInfoWithLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter_(LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *publicKey);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoUtilSubjectPublicKeyInfoFactory)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // SubjectPublicKeyInfoFactory_H