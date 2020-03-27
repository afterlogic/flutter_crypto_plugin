//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/pqc/crypto/xmss/XMSSReducedSignature.java
//

#ifndef XMSSReducedSignature_H
#define XMSSReducedSignature_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "XMSSStoreableObjectInterface.h"

@class IOSByteArray;
@class LibOrgBouncycastlePqcCryptoXmssWOTSPlusSignature;
@class LibOrgBouncycastlePqcCryptoXmssXMSSParameters;
@class LibOrgBouncycastlePqcCryptoXmssXMSSReducedSignature_Builder;
@protocol JavaUtilList;

@interface LibOrgBouncycastlePqcCryptoXmssXMSSReducedSignature : NSObject < LibOrgBouncycastlePqcCryptoXmssXMSSStoreableObjectInterface >

#pragma mark Public

- (id<JavaUtilList>)getAuthPath;

- (LibOrgBouncycastlePqcCryptoXmssXMSSParameters *)getParams;

- (LibOrgBouncycastlePqcCryptoXmssWOTSPlusSignature *)getWOTSPlusSignature;

- (IOSByteArray *)toByteArray;

#pragma mark Protected

- (instancetype __nonnull)initWithLibOrgBouncycastlePqcCryptoXmssXMSSReducedSignature_Builder:(LibOrgBouncycastlePqcCryptoXmssXMSSReducedSignature_Builder *)builder;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastlePqcCryptoXmssXMSSReducedSignature)

FOUNDATION_EXPORT void LibOrgBouncycastlePqcCryptoXmssXMSSReducedSignature_initWithLibOrgBouncycastlePqcCryptoXmssXMSSReducedSignature_Builder_(LibOrgBouncycastlePqcCryptoXmssXMSSReducedSignature *self, LibOrgBouncycastlePqcCryptoXmssXMSSReducedSignature_Builder *builder);

FOUNDATION_EXPORT LibOrgBouncycastlePqcCryptoXmssXMSSReducedSignature *new_LibOrgBouncycastlePqcCryptoXmssXMSSReducedSignature_initWithLibOrgBouncycastlePqcCryptoXmssXMSSReducedSignature_Builder_(LibOrgBouncycastlePqcCryptoXmssXMSSReducedSignature_Builder *builder) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastlePqcCryptoXmssXMSSReducedSignature *create_LibOrgBouncycastlePqcCryptoXmssXMSSReducedSignature_initWithLibOrgBouncycastlePqcCryptoXmssXMSSReducedSignature_Builder_(LibOrgBouncycastlePqcCryptoXmssXMSSReducedSignature_Builder *builder);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastlePqcCryptoXmssXMSSReducedSignature)

@interface LibOrgBouncycastlePqcCryptoXmssXMSSReducedSignature_Builder : NSObject

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastlePqcCryptoXmssXMSSParameters:(LibOrgBouncycastlePqcCryptoXmssXMSSParameters *)params;

- (LibOrgBouncycastlePqcCryptoXmssXMSSReducedSignature *)build;

- (LibOrgBouncycastlePqcCryptoXmssXMSSReducedSignature_Builder *)withAuthPathWithJavaUtilList:(id<JavaUtilList>)val;

- (LibOrgBouncycastlePqcCryptoXmssXMSSReducedSignature_Builder *)withReducedSignatureWithByteArray:(IOSByteArray *)val;

- (LibOrgBouncycastlePqcCryptoXmssXMSSReducedSignature_Builder *)withWOTSPlusSignatureWithLibOrgBouncycastlePqcCryptoXmssWOTSPlusSignature:(LibOrgBouncycastlePqcCryptoXmssWOTSPlusSignature *)val;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastlePqcCryptoXmssXMSSReducedSignature_Builder)

FOUNDATION_EXPORT void LibOrgBouncycastlePqcCryptoXmssXMSSReducedSignature_Builder_initWithLibOrgBouncycastlePqcCryptoXmssXMSSParameters_(LibOrgBouncycastlePqcCryptoXmssXMSSReducedSignature_Builder *self, LibOrgBouncycastlePqcCryptoXmssXMSSParameters *params);

FOUNDATION_EXPORT LibOrgBouncycastlePqcCryptoXmssXMSSReducedSignature_Builder *new_LibOrgBouncycastlePqcCryptoXmssXMSSReducedSignature_Builder_initWithLibOrgBouncycastlePqcCryptoXmssXMSSParameters_(LibOrgBouncycastlePqcCryptoXmssXMSSParameters *params) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastlePqcCryptoXmssXMSSReducedSignature_Builder *create_LibOrgBouncycastlePqcCryptoXmssXMSSReducedSignature_Builder_initWithLibOrgBouncycastlePqcCryptoXmssXMSSParameters_(LibOrgBouncycastlePqcCryptoXmssXMSSParameters *params);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastlePqcCryptoXmssXMSSReducedSignature_Builder)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // XMSSReducedSignature_H
