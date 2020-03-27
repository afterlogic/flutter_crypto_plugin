//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jcajce/util/AlgorithmParametersUtils.java
//

#ifndef AlgorithmParametersUtils_H
#define AlgorithmParametersUtils_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class JavaSecurityAlgorithmParameters;
@protocol LibOrgBouncycastleAsn1ASN1Encodable;

@interface LibOrgBouncycastleJcajceUtilAlgorithmParametersUtils : NSObject

#pragma mark Public

+ (id<LibOrgBouncycastleAsn1ASN1Encodable>)extractParametersWithJavaSecurityAlgorithmParameters:(JavaSecurityAlgorithmParameters *)params;

+ (void)loadParametersWithJavaSecurityAlgorithmParameters:(JavaSecurityAlgorithmParameters *)params
                  withLibOrgBouncycastleAsn1ASN1Encodable:(id<LibOrgBouncycastleAsn1ASN1Encodable>)sParams;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceUtilAlgorithmParametersUtils)

FOUNDATION_EXPORT id<LibOrgBouncycastleAsn1ASN1Encodable> LibOrgBouncycastleJcajceUtilAlgorithmParametersUtils_extractParametersWithJavaSecurityAlgorithmParameters_(JavaSecurityAlgorithmParameters *params);

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceUtilAlgorithmParametersUtils_loadParametersWithJavaSecurityAlgorithmParameters_withLibOrgBouncycastleAsn1ASN1Encodable_(JavaSecurityAlgorithmParameters *params, id<LibOrgBouncycastleAsn1ASN1Encodable> sParams);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceUtilAlgorithmParametersUtils)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // AlgorithmParametersUtils_H
