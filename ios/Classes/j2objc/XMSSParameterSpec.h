//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/pqc/jcajce/spec/XMSSParameterSpec.java
//

#ifndef XMSSParameterSpec_H
#define XMSSParameterSpec_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "java/security/spec/AlgorithmParameterSpec.h"

@interface LibOrgBouncycastlePqcJcajceSpecXMSSParameterSpec : NSObject < JavaSecuritySpecAlgorithmParameterSpec >
@property (readonly, copy, class) NSString *SHA256 NS_SWIFT_NAME(SHA256);
@property (readonly, copy, class) NSString *SHA512 NS_SWIFT_NAME(SHA512);
@property (readonly, copy, class) NSString *SHAKE128 NS_SWIFT_NAME(SHAKE128);
@property (readonly, copy, class) NSString *SHAKE256 NS_SWIFT_NAME(SHAKE256);

+ (NSString *)SHA256;

+ (NSString *)SHA512;

+ (NSString *)SHAKE128;

+ (NSString *)SHAKE256;

#pragma mark Public

- (instancetype __nonnull)initWithInt:(jint)height
                         withNSString:(NSString *)treeDigest;

- (jint)getHeight;

- (NSString *)getTreeDigest;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastlePqcJcajceSpecXMSSParameterSpec)

inline NSString *LibOrgBouncycastlePqcJcajceSpecXMSSParameterSpec_get_SHA256(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT NSString *LibOrgBouncycastlePqcJcajceSpecXMSSParameterSpec_SHA256;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastlePqcJcajceSpecXMSSParameterSpec, SHA256, NSString *)

inline NSString *LibOrgBouncycastlePqcJcajceSpecXMSSParameterSpec_get_SHA512(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT NSString *LibOrgBouncycastlePqcJcajceSpecXMSSParameterSpec_SHA512;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastlePqcJcajceSpecXMSSParameterSpec, SHA512, NSString *)

inline NSString *LibOrgBouncycastlePqcJcajceSpecXMSSParameterSpec_get_SHAKE128(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT NSString *LibOrgBouncycastlePqcJcajceSpecXMSSParameterSpec_SHAKE128;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastlePqcJcajceSpecXMSSParameterSpec, SHAKE128, NSString *)

inline NSString *LibOrgBouncycastlePqcJcajceSpecXMSSParameterSpec_get_SHAKE256(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT NSString *LibOrgBouncycastlePqcJcajceSpecXMSSParameterSpec_SHAKE256;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastlePqcJcajceSpecXMSSParameterSpec, SHAKE256, NSString *)

FOUNDATION_EXPORT void LibOrgBouncycastlePqcJcajceSpecXMSSParameterSpec_initWithInt_withNSString_(LibOrgBouncycastlePqcJcajceSpecXMSSParameterSpec *self, jint height, NSString *treeDigest);

FOUNDATION_EXPORT LibOrgBouncycastlePqcJcajceSpecXMSSParameterSpec *new_LibOrgBouncycastlePqcJcajceSpecXMSSParameterSpec_initWithInt_withNSString_(jint height, NSString *treeDigest) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastlePqcJcajceSpecXMSSParameterSpec *create_LibOrgBouncycastlePqcJcajceSpecXMSSParameterSpec_initWithInt_withNSString_(jint height, NSString *treeDigest);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastlePqcJcajceSpecXMSSParameterSpec)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // XMSSParameterSpec_H
