//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/pqc/jcajce/spec/SPHINCS256KeyGenParameterSpec.java
//

#ifndef SPHINCS256KeyGenParameterSpec_H
#define SPHINCS256KeyGenParameterSpec_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "java/security/spec/AlgorithmParameterSpec.h"

@interface LibOrgBouncycastlePqcJcajceSpecSPHINCS256KeyGenParameterSpec : NSObject < JavaSecuritySpecAlgorithmParameterSpec >
@property (readonly, copy, class) NSString *SHA512_256 NS_SWIFT_NAME(SHA512_256);
@property (readonly, copy, class) NSString *SHA3_256 NS_SWIFT_NAME(SHA3_256);

+ (NSString *)SHA512_256;

+ (NSString *)SHA3_256;

#pragma mark Public

- (instancetype __nonnull)init;

- (instancetype __nonnull)initWithNSString:(NSString *)treeHash;

- (NSString *)getTreeDigest;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastlePqcJcajceSpecSPHINCS256KeyGenParameterSpec)

inline NSString *LibOrgBouncycastlePqcJcajceSpecSPHINCS256KeyGenParameterSpec_get_SHA512_256(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT NSString *LibOrgBouncycastlePqcJcajceSpecSPHINCS256KeyGenParameterSpec_SHA512_256;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastlePqcJcajceSpecSPHINCS256KeyGenParameterSpec, SHA512_256, NSString *)

inline NSString *LibOrgBouncycastlePqcJcajceSpecSPHINCS256KeyGenParameterSpec_get_SHA3_256(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT NSString *LibOrgBouncycastlePqcJcajceSpecSPHINCS256KeyGenParameterSpec_SHA3_256;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastlePqcJcajceSpecSPHINCS256KeyGenParameterSpec, SHA3_256, NSString *)

FOUNDATION_EXPORT void LibOrgBouncycastlePqcJcajceSpecSPHINCS256KeyGenParameterSpec_init(LibOrgBouncycastlePqcJcajceSpecSPHINCS256KeyGenParameterSpec *self);

FOUNDATION_EXPORT LibOrgBouncycastlePqcJcajceSpecSPHINCS256KeyGenParameterSpec *new_LibOrgBouncycastlePqcJcajceSpecSPHINCS256KeyGenParameterSpec_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastlePqcJcajceSpecSPHINCS256KeyGenParameterSpec *create_LibOrgBouncycastlePqcJcajceSpecSPHINCS256KeyGenParameterSpec_init(void);

FOUNDATION_EXPORT void LibOrgBouncycastlePqcJcajceSpecSPHINCS256KeyGenParameterSpec_initWithNSString_(LibOrgBouncycastlePqcJcajceSpecSPHINCS256KeyGenParameterSpec *self, NSString *treeHash);

FOUNDATION_EXPORT LibOrgBouncycastlePqcJcajceSpecSPHINCS256KeyGenParameterSpec *new_LibOrgBouncycastlePqcJcajceSpecSPHINCS256KeyGenParameterSpec_initWithNSString_(NSString *treeHash) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastlePqcJcajceSpecSPHINCS256KeyGenParameterSpec *create_LibOrgBouncycastlePqcJcajceSpecSPHINCS256KeyGenParameterSpec_initWithNSString_(NSString *treeHash);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastlePqcJcajceSpecSPHINCS256KeyGenParameterSpec)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // SPHINCS256KeyGenParameterSpec_H
