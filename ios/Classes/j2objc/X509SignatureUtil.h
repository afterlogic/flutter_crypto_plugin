//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jce/provider/X509SignatureUtil.java
//

#ifndef X509SignatureUtil_H
#define X509SignatureUtil_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class JavaSecuritySignature;
@class LibOrgBouncycastleAsn1X509AlgorithmIdentifier;
@protocol LibOrgBouncycastleAsn1ASN1Encodable;

@interface LibOrgBouncycastleJceProviderX509SignatureUtil : NSObject

#pragma mark Package-Private

- (instancetype __nonnull)init;

+ (NSString *)getSignatureNameWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier:(LibOrgBouncycastleAsn1X509AlgorithmIdentifier *)sigAlgId;

+ (void)setSignatureParametersWithJavaSecuritySignature:(JavaSecuritySignature *)signature
                withLibOrgBouncycastleAsn1ASN1Encodable:(id<LibOrgBouncycastleAsn1ASN1Encodable>)params;

@end

J2OBJC_STATIC_INIT(LibOrgBouncycastleJceProviderX509SignatureUtil)

FOUNDATION_EXPORT void LibOrgBouncycastleJceProviderX509SignatureUtil_init(LibOrgBouncycastleJceProviderX509SignatureUtil *self);

FOUNDATION_EXPORT LibOrgBouncycastleJceProviderX509SignatureUtil *new_LibOrgBouncycastleJceProviderX509SignatureUtil_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJceProviderX509SignatureUtil *create_LibOrgBouncycastleJceProviderX509SignatureUtil_init(void);

FOUNDATION_EXPORT void LibOrgBouncycastleJceProviderX509SignatureUtil_setSignatureParametersWithJavaSecuritySignature_withLibOrgBouncycastleAsn1ASN1Encodable_(JavaSecuritySignature *signature, id<LibOrgBouncycastleAsn1ASN1Encodable> params);

FOUNDATION_EXPORT NSString *LibOrgBouncycastleJceProviderX509SignatureUtil_getSignatureNameWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_(LibOrgBouncycastleAsn1X509AlgorithmIdentifier *sigAlgId);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJceProviderX509SignatureUtil)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // X509SignatureUtil_H
