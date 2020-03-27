//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/parsers/DHIESPublicKeyParser.java
//

#ifndef DHIESPublicKeyParser_H
#define DHIESPublicKeyParser_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "KeyParser.h"

@class JavaIoInputStream;
@class LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter;
@class LibOrgBouncycastleCryptoParamsDHParameters;

@interface LibOrgBouncycastleCryptoParsersDHIESPublicKeyParser : NSObject < LibOrgBouncycastleCryptoKeyParser >

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoParamsDHParameters:(LibOrgBouncycastleCryptoParamsDHParameters *)dhParams;

- (LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *)readKeyWithJavaIoInputStream:(JavaIoInputStream *)stream;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleCryptoParsersDHIESPublicKeyParser)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoParsersDHIESPublicKeyParser_initWithLibOrgBouncycastleCryptoParamsDHParameters_(LibOrgBouncycastleCryptoParsersDHIESPublicKeyParser *self, LibOrgBouncycastleCryptoParamsDHParameters *dhParams);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoParsersDHIESPublicKeyParser *new_LibOrgBouncycastleCryptoParsersDHIESPublicKeyParser_initWithLibOrgBouncycastleCryptoParamsDHParameters_(LibOrgBouncycastleCryptoParamsDHParameters *dhParams) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoParsersDHIESPublicKeyParser *create_LibOrgBouncycastleCryptoParsersDHIESPublicKeyParser_initWithLibOrgBouncycastleCryptoParamsDHParameters_(LibOrgBouncycastleCryptoParamsDHParameters *dhParams);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoParsersDHIESPublicKeyParser)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // DHIESPublicKeyParser_H
