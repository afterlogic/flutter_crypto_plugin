//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/CryptoServicesRegistrar.java
//

#ifndef CryptoServicesRegistrar_H
#define CryptoServicesRegistrar_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class IOSObjectArray;
@class JavaSecuritySecureRandom;
@class LibOrgBouncycastleCryptoCryptoServicesRegistrar_Property;

@interface LibOrgBouncycastleCryptoCryptoServicesRegistrar : NSObject

#pragma mark Public

+ (IOSObjectArray *)clearGlobalPropertyWithLibOrgBouncycastleCryptoCryptoServicesRegistrar_Property:(LibOrgBouncycastleCryptoCryptoServicesRegistrar_Property *)property;

+ (IOSObjectArray *)clearThreadPropertyWithLibOrgBouncycastleCryptoCryptoServicesRegistrar_Property:(LibOrgBouncycastleCryptoCryptoServicesRegistrar_Property *)property;

+ (id)getPropertyWithLibOrgBouncycastleCryptoCryptoServicesRegistrar_Property:(LibOrgBouncycastleCryptoCryptoServicesRegistrar_Property *)property;

+ (JavaSecuritySecureRandom *)getSecureRandom;

+ (IOSObjectArray *)getSizedPropertyWithLibOrgBouncycastleCryptoCryptoServicesRegistrar_Property:(LibOrgBouncycastleCryptoCryptoServicesRegistrar_Property *)property;

+ (id)getSizedPropertyWithLibOrgBouncycastleCryptoCryptoServicesRegistrar_Property:(LibOrgBouncycastleCryptoCryptoServicesRegistrar_Property *)property
                                                                           withInt:(jint)size;

+ (void)setGlobalPropertyWithLibOrgBouncycastleCryptoCryptoServicesRegistrar_Property:(LibOrgBouncycastleCryptoCryptoServicesRegistrar_Property *)property
                                                                    withNSObjectArray:(IOSObjectArray *)propertyValue;

+ (void)setSecureRandomWithJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)secureRandom;

+ (void)setThreadPropertyWithLibOrgBouncycastleCryptoCryptoServicesRegistrar_Property:(LibOrgBouncycastleCryptoCryptoServicesRegistrar_Property *)property
                                                                    withNSObjectArray:(IOSObjectArray *)propertyValue;

@end

J2OBJC_STATIC_INIT(LibOrgBouncycastleCryptoCryptoServicesRegistrar)

FOUNDATION_EXPORT JavaSecuritySecureRandom *LibOrgBouncycastleCryptoCryptoServicesRegistrar_getSecureRandom(void);

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoCryptoServicesRegistrar_setSecureRandomWithJavaSecuritySecureRandom_(JavaSecuritySecureRandom *secureRandom);

FOUNDATION_EXPORT id LibOrgBouncycastleCryptoCryptoServicesRegistrar_getPropertyWithLibOrgBouncycastleCryptoCryptoServicesRegistrar_Property_(LibOrgBouncycastleCryptoCryptoServicesRegistrar_Property *property);

FOUNDATION_EXPORT IOSObjectArray *LibOrgBouncycastleCryptoCryptoServicesRegistrar_getSizedPropertyWithLibOrgBouncycastleCryptoCryptoServicesRegistrar_Property_(LibOrgBouncycastleCryptoCryptoServicesRegistrar_Property *property);

FOUNDATION_EXPORT id LibOrgBouncycastleCryptoCryptoServicesRegistrar_getSizedPropertyWithLibOrgBouncycastleCryptoCryptoServicesRegistrar_Property_withInt_(LibOrgBouncycastleCryptoCryptoServicesRegistrar_Property *property, jint size);

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoCryptoServicesRegistrar_setThreadPropertyWithLibOrgBouncycastleCryptoCryptoServicesRegistrar_Property_withNSObjectArray_(LibOrgBouncycastleCryptoCryptoServicesRegistrar_Property *property, IOSObjectArray *propertyValue);

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoCryptoServicesRegistrar_setGlobalPropertyWithLibOrgBouncycastleCryptoCryptoServicesRegistrar_Property_withNSObjectArray_(LibOrgBouncycastleCryptoCryptoServicesRegistrar_Property *property, IOSObjectArray *propertyValue);

FOUNDATION_EXPORT IOSObjectArray *LibOrgBouncycastleCryptoCryptoServicesRegistrar_clearGlobalPropertyWithLibOrgBouncycastleCryptoCryptoServicesRegistrar_Property_(LibOrgBouncycastleCryptoCryptoServicesRegistrar_Property *property);

FOUNDATION_EXPORT IOSObjectArray *LibOrgBouncycastleCryptoCryptoServicesRegistrar_clearThreadPropertyWithLibOrgBouncycastleCryptoCryptoServicesRegistrar_Property_(LibOrgBouncycastleCryptoCryptoServicesRegistrar_Property *property);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoCryptoServicesRegistrar)

@interface LibOrgBouncycastleCryptoCryptoServicesRegistrar_Property : NSObject
@property (readonly, class) LibOrgBouncycastleCryptoCryptoServicesRegistrar_Property *EC_IMPLICITLY_CA NS_SWIFT_NAME(EC_IMPLICITLY_CA);
@property (readonly, class) LibOrgBouncycastleCryptoCryptoServicesRegistrar_Property *DH_DEFAULT_PARAMS NS_SWIFT_NAME(DH_DEFAULT_PARAMS);
@property (readonly, class) LibOrgBouncycastleCryptoCryptoServicesRegistrar_Property *DSA_DEFAULT_PARAMS NS_SWIFT_NAME(DSA_DEFAULT_PARAMS);

+ (LibOrgBouncycastleCryptoCryptoServicesRegistrar_Property *)EC_IMPLICITLY_CA;

+ (LibOrgBouncycastleCryptoCryptoServicesRegistrar_Property *)DH_DEFAULT_PARAMS;

+ (LibOrgBouncycastleCryptoCryptoServicesRegistrar_Property *)DSA_DEFAULT_PARAMS;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_STATIC_INIT(LibOrgBouncycastleCryptoCryptoServicesRegistrar_Property)

inline LibOrgBouncycastleCryptoCryptoServicesRegistrar_Property *LibOrgBouncycastleCryptoCryptoServicesRegistrar_Property_get_EC_IMPLICITLY_CA(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT LibOrgBouncycastleCryptoCryptoServicesRegistrar_Property *LibOrgBouncycastleCryptoCryptoServicesRegistrar_Property_EC_IMPLICITLY_CA;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleCryptoCryptoServicesRegistrar_Property, EC_IMPLICITLY_CA, LibOrgBouncycastleCryptoCryptoServicesRegistrar_Property *)

inline LibOrgBouncycastleCryptoCryptoServicesRegistrar_Property *LibOrgBouncycastleCryptoCryptoServicesRegistrar_Property_get_DH_DEFAULT_PARAMS(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT LibOrgBouncycastleCryptoCryptoServicesRegistrar_Property *LibOrgBouncycastleCryptoCryptoServicesRegistrar_Property_DH_DEFAULT_PARAMS;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleCryptoCryptoServicesRegistrar_Property, DH_DEFAULT_PARAMS, LibOrgBouncycastleCryptoCryptoServicesRegistrar_Property *)

inline LibOrgBouncycastleCryptoCryptoServicesRegistrar_Property *LibOrgBouncycastleCryptoCryptoServicesRegistrar_Property_get_DSA_DEFAULT_PARAMS(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT LibOrgBouncycastleCryptoCryptoServicesRegistrar_Property *LibOrgBouncycastleCryptoCryptoServicesRegistrar_Property_DSA_DEFAULT_PARAMS;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleCryptoCryptoServicesRegistrar_Property, DSA_DEFAULT_PARAMS, LibOrgBouncycastleCryptoCryptoServicesRegistrar_Property *)

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoCryptoServicesRegistrar_Property)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // CryptoServicesRegistrar_H