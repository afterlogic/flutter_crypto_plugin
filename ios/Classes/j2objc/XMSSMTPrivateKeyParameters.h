//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/pqc/crypto/xmss/XMSSMTPrivateKeyParameters.java
//

#ifndef XMSSMTPrivateKeyParameters_H
#define XMSSMTPrivateKeyParameters_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "XMSSMTKeyParameters.h"
#include "XMSSStoreableObjectInterface.h"

@class IOSByteArray;
@class LibOrgBouncycastlePqcCryptoXmssBDSStateMap;
@class LibOrgBouncycastlePqcCryptoXmssXMSSMTParameters;
@class LibOrgBouncycastlePqcCryptoXmssXMSSParameters;

@interface LibOrgBouncycastlePqcCryptoXmssXMSSMTPrivateKeyParameters : LibOrgBouncycastlePqcCryptoXmssXMSSMTKeyParameters < LibOrgBouncycastlePqcCryptoXmssXMSSStoreableObjectInterface >

#pragma mark Public

- (jlong)getIndex;

- (LibOrgBouncycastlePqcCryptoXmssXMSSMTPrivateKeyParameters *)getNextKey;

- (LibOrgBouncycastlePqcCryptoXmssXMSSMTParameters *)getParameters;

- (IOSByteArray *)getPublicSeed;

- (IOSByteArray *)getRoot;

- (IOSByteArray *)getSecretKeyPRF;

- (IOSByteArray *)getSecretKeySeed;

- (jlong)getUsagesRemaining;

- (IOSByteArray *)toByteArray;

#pragma mark Package-Private

- (LibOrgBouncycastlePqcCryptoXmssBDSStateMap *)getBDSState;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithBoolean:(jboolean)arg0
                             withNSString:(NSString *)arg1 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastlePqcCryptoXmssXMSSMTPrivateKeyParameters)

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastlePqcCryptoXmssXMSSMTPrivateKeyParameters)

@interface LibOrgBouncycastlePqcCryptoXmssXMSSMTPrivateKeyParameters_Builder : NSObject

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastlePqcCryptoXmssXMSSMTParameters:(LibOrgBouncycastlePqcCryptoXmssXMSSMTParameters *)params;

- (LibOrgBouncycastlePqcCryptoXmssXMSSMTPrivateKeyParameters *)build;

- (LibOrgBouncycastlePqcCryptoXmssXMSSMTPrivateKeyParameters_Builder *)withBDSStateWithLibOrgBouncycastlePqcCryptoXmssBDSStateMap:(LibOrgBouncycastlePqcCryptoXmssBDSStateMap *)val;

- (LibOrgBouncycastlePqcCryptoXmssXMSSMTPrivateKeyParameters_Builder *)withIndexWithLong:(jlong)val;

- (LibOrgBouncycastlePqcCryptoXmssXMSSMTPrivateKeyParameters_Builder *)withPrivateKeyWithByteArray:(IOSByteArray *)privateKeyVal
                                                 withLibOrgBouncycastlePqcCryptoXmssXMSSParameters:(LibOrgBouncycastlePqcCryptoXmssXMSSParameters *)xmssVal;

- (LibOrgBouncycastlePqcCryptoXmssXMSSMTPrivateKeyParameters_Builder *)withPublicSeedWithByteArray:(IOSByteArray *)val;

- (LibOrgBouncycastlePqcCryptoXmssXMSSMTPrivateKeyParameters_Builder *)withRootWithByteArray:(IOSByteArray *)val;

- (LibOrgBouncycastlePqcCryptoXmssXMSSMTPrivateKeyParameters_Builder *)withSecretKeyPRFWithByteArray:(IOSByteArray *)val;

- (LibOrgBouncycastlePqcCryptoXmssXMSSMTPrivateKeyParameters_Builder *)withSecretKeySeedWithByteArray:(IOSByteArray *)val;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastlePqcCryptoXmssXMSSMTPrivateKeyParameters_Builder)

FOUNDATION_EXPORT void LibOrgBouncycastlePqcCryptoXmssXMSSMTPrivateKeyParameters_Builder_initWithLibOrgBouncycastlePqcCryptoXmssXMSSMTParameters_(LibOrgBouncycastlePqcCryptoXmssXMSSMTPrivateKeyParameters_Builder *self, LibOrgBouncycastlePqcCryptoXmssXMSSMTParameters *params);

FOUNDATION_EXPORT LibOrgBouncycastlePqcCryptoXmssXMSSMTPrivateKeyParameters_Builder *new_LibOrgBouncycastlePqcCryptoXmssXMSSMTPrivateKeyParameters_Builder_initWithLibOrgBouncycastlePqcCryptoXmssXMSSMTParameters_(LibOrgBouncycastlePqcCryptoXmssXMSSMTParameters *params) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastlePqcCryptoXmssXMSSMTPrivateKeyParameters_Builder *create_LibOrgBouncycastlePqcCryptoXmssXMSSMTPrivateKeyParameters_Builder_initWithLibOrgBouncycastlePqcCryptoXmssXMSSMTParameters_(LibOrgBouncycastlePqcCryptoXmssXMSSMTParameters *params);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastlePqcCryptoXmssXMSSMTPrivateKeyParameters_Builder)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // XMSSMTPrivateKeyParameters_H
