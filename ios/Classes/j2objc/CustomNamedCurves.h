//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/ec/CustomNamedCurves.java
//

#ifndef CustomNamedCurves_H
#define CustomNamedCurves_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class JavaUtilHashtable;
@class JavaUtilVector;
@class LibOrgBouncycastleAsn1ASN1ObjectIdentifier;
@class LibOrgBouncycastleAsn1X9X9ECParameters;
@class LibOrgBouncycastleAsn1X9X9ECParametersHolder;
@protocol JavaUtilEnumeration;

@interface LibOrgBouncycastleCryptoEcCustomNamedCurves : NSObject
@property (class) LibOrgBouncycastleAsn1X9X9ECParametersHolder *curve25519 NS_SWIFT_NAME(curve25519);
@property (class) LibOrgBouncycastleAsn1X9X9ECParametersHolder *secp128r1 NS_SWIFT_NAME(secp128r1);
@property (class) LibOrgBouncycastleAsn1X9X9ECParametersHolder *secp160k1 NS_SWIFT_NAME(secp160k1);
@property (class) LibOrgBouncycastleAsn1X9X9ECParametersHolder *secp160r1 NS_SWIFT_NAME(secp160r1);
@property (class) LibOrgBouncycastleAsn1X9X9ECParametersHolder *secp160r2 NS_SWIFT_NAME(secp160r2);
@property (class) LibOrgBouncycastleAsn1X9X9ECParametersHolder *secp192k1 NS_SWIFT_NAME(secp192k1);
@property (class) LibOrgBouncycastleAsn1X9X9ECParametersHolder *secp192r1 NS_SWIFT_NAME(secp192r1);
@property (class) LibOrgBouncycastleAsn1X9X9ECParametersHolder *secp224k1 NS_SWIFT_NAME(secp224k1);
@property (class) LibOrgBouncycastleAsn1X9X9ECParametersHolder *secp224r1 NS_SWIFT_NAME(secp224r1);
@property (class) LibOrgBouncycastleAsn1X9X9ECParametersHolder *secp256k1 NS_SWIFT_NAME(secp256k1);
@property (class) LibOrgBouncycastleAsn1X9X9ECParametersHolder *secp256r1 NS_SWIFT_NAME(secp256r1);
@property (class) LibOrgBouncycastleAsn1X9X9ECParametersHolder *secp384r1 NS_SWIFT_NAME(secp384r1);
@property (class) LibOrgBouncycastleAsn1X9X9ECParametersHolder *secp521r1 NS_SWIFT_NAME(secp521r1);
@property (class) LibOrgBouncycastleAsn1X9X9ECParametersHolder *sect113r1 NS_SWIFT_NAME(sect113r1);
@property (class) LibOrgBouncycastleAsn1X9X9ECParametersHolder *sect113r2 NS_SWIFT_NAME(sect113r2);
@property (class) LibOrgBouncycastleAsn1X9X9ECParametersHolder *sect131r1 NS_SWIFT_NAME(sect131r1);
@property (class) LibOrgBouncycastleAsn1X9X9ECParametersHolder *sect131r2 NS_SWIFT_NAME(sect131r2);
@property (class) LibOrgBouncycastleAsn1X9X9ECParametersHolder *sect163k1 NS_SWIFT_NAME(sect163k1);
@property (class) LibOrgBouncycastleAsn1X9X9ECParametersHolder *sect163r1 NS_SWIFT_NAME(sect163r1);
@property (class) LibOrgBouncycastleAsn1X9X9ECParametersHolder *sect163r2 NS_SWIFT_NAME(sect163r2);
@property (class) LibOrgBouncycastleAsn1X9X9ECParametersHolder *sect193r1 NS_SWIFT_NAME(sect193r1);
@property (class) LibOrgBouncycastleAsn1X9X9ECParametersHolder *sect193r2 NS_SWIFT_NAME(sect193r2);
@property (class) LibOrgBouncycastleAsn1X9X9ECParametersHolder *sect233k1 NS_SWIFT_NAME(sect233k1);
@property (class) LibOrgBouncycastleAsn1X9X9ECParametersHolder *sect233r1 NS_SWIFT_NAME(sect233r1);
@property (class) LibOrgBouncycastleAsn1X9X9ECParametersHolder *sect239k1 NS_SWIFT_NAME(sect239k1);
@property (class) LibOrgBouncycastleAsn1X9X9ECParametersHolder *sect283k1 NS_SWIFT_NAME(sect283k1);
@property (class) LibOrgBouncycastleAsn1X9X9ECParametersHolder *sect283r1 NS_SWIFT_NAME(sect283r1);
@property (class) LibOrgBouncycastleAsn1X9X9ECParametersHolder *sect409k1 NS_SWIFT_NAME(sect409k1);
@property (class) LibOrgBouncycastleAsn1X9X9ECParametersHolder *sect409r1 NS_SWIFT_NAME(sect409r1);
@property (class) LibOrgBouncycastleAsn1X9X9ECParametersHolder *sect571k1 NS_SWIFT_NAME(sect571k1);
@property (class) LibOrgBouncycastleAsn1X9X9ECParametersHolder *sect571r1 NS_SWIFT_NAME(sect571r1);
@property (class) LibOrgBouncycastleAsn1X9X9ECParametersHolder *sm2p256v1 NS_SWIFT_NAME(sm2p256v1);
@property (readonly, class) JavaUtilHashtable *nameToCurve NS_SWIFT_NAME(nameToCurve);
@property (readonly, class) JavaUtilHashtable *nameToOID NS_SWIFT_NAME(nameToOID);
@property (readonly, class) JavaUtilHashtable *oidToCurve NS_SWIFT_NAME(oidToCurve);
@property (readonly, class) JavaUtilHashtable *oidToName NS_SWIFT_NAME(oidToName);
@property (readonly, nonatomic, getter=getNames, class) JavaUtilVector *names NS_SWIFT_NAME(names);

+ (LibOrgBouncycastleAsn1X9X9ECParametersHolder *)curve25519;

+ (void)setCurve25519:(LibOrgBouncycastleAsn1X9X9ECParametersHolder *)value;

+ (LibOrgBouncycastleAsn1X9X9ECParametersHolder *)secp128r1;

+ (void)setSecp128r1:(LibOrgBouncycastleAsn1X9X9ECParametersHolder *)value;

+ (LibOrgBouncycastleAsn1X9X9ECParametersHolder *)secp160k1;

+ (void)setSecp160k1:(LibOrgBouncycastleAsn1X9X9ECParametersHolder *)value;

+ (LibOrgBouncycastleAsn1X9X9ECParametersHolder *)secp160r1;

+ (void)setSecp160r1:(LibOrgBouncycastleAsn1X9X9ECParametersHolder *)value;

+ (LibOrgBouncycastleAsn1X9X9ECParametersHolder *)secp160r2;

+ (void)setSecp160r2:(LibOrgBouncycastleAsn1X9X9ECParametersHolder *)value;

+ (LibOrgBouncycastleAsn1X9X9ECParametersHolder *)secp192k1;

+ (void)setSecp192k1:(LibOrgBouncycastleAsn1X9X9ECParametersHolder *)value;

+ (LibOrgBouncycastleAsn1X9X9ECParametersHolder *)secp192r1;

+ (void)setSecp192r1:(LibOrgBouncycastleAsn1X9X9ECParametersHolder *)value;

+ (LibOrgBouncycastleAsn1X9X9ECParametersHolder *)secp224k1;

+ (void)setSecp224k1:(LibOrgBouncycastleAsn1X9X9ECParametersHolder *)value;

+ (LibOrgBouncycastleAsn1X9X9ECParametersHolder *)secp224r1;

+ (void)setSecp224r1:(LibOrgBouncycastleAsn1X9X9ECParametersHolder *)value;

+ (LibOrgBouncycastleAsn1X9X9ECParametersHolder *)secp256k1;

+ (void)setSecp256k1:(LibOrgBouncycastleAsn1X9X9ECParametersHolder *)value;

+ (LibOrgBouncycastleAsn1X9X9ECParametersHolder *)secp256r1;

+ (void)setSecp256r1:(LibOrgBouncycastleAsn1X9X9ECParametersHolder *)value;

+ (LibOrgBouncycastleAsn1X9X9ECParametersHolder *)secp384r1;

+ (void)setSecp384r1:(LibOrgBouncycastleAsn1X9X9ECParametersHolder *)value;

+ (LibOrgBouncycastleAsn1X9X9ECParametersHolder *)secp521r1;

+ (void)setSecp521r1:(LibOrgBouncycastleAsn1X9X9ECParametersHolder *)value;

+ (LibOrgBouncycastleAsn1X9X9ECParametersHolder *)sect113r1;

+ (void)setSect113r1:(LibOrgBouncycastleAsn1X9X9ECParametersHolder *)value;

+ (LibOrgBouncycastleAsn1X9X9ECParametersHolder *)sect113r2;

+ (void)setSect113r2:(LibOrgBouncycastleAsn1X9X9ECParametersHolder *)value;

+ (LibOrgBouncycastleAsn1X9X9ECParametersHolder *)sect131r1;

+ (void)setSect131r1:(LibOrgBouncycastleAsn1X9X9ECParametersHolder *)value;

+ (LibOrgBouncycastleAsn1X9X9ECParametersHolder *)sect131r2;

+ (void)setSect131r2:(LibOrgBouncycastleAsn1X9X9ECParametersHolder *)value;

+ (LibOrgBouncycastleAsn1X9X9ECParametersHolder *)sect163k1;

+ (void)setSect163k1:(LibOrgBouncycastleAsn1X9X9ECParametersHolder *)value;

+ (LibOrgBouncycastleAsn1X9X9ECParametersHolder *)sect163r1;

+ (void)setSect163r1:(LibOrgBouncycastleAsn1X9X9ECParametersHolder *)value;

+ (LibOrgBouncycastleAsn1X9X9ECParametersHolder *)sect163r2;

+ (void)setSect163r2:(LibOrgBouncycastleAsn1X9X9ECParametersHolder *)value;

+ (LibOrgBouncycastleAsn1X9X9ECParametersHolder *)sect193r1;

+ (void)setSect193r1:(LibOrgBouncycastleAsn1X9X9ECParametersHolder *)value;

+ (LibOrgBouncycastleAsn1X9X9ECParametersHolder *)sect193r2;

+ (void)setSect193r2:(LibOrgBouncycastleAsn1X9X9ECParametersHolder *)value;

+ (LibOrgBouncycastleAsn1X9X9ECParametersHolder *)sect233k1;

+ (void)setSect233k1:(LibOrgBouncycastleAsn1X9X9ECParametersHolder *)value;

+ (LibOrgBouncycastleAsn1X9X9ECParametersHolder *)sect233r1;

+ (void)setSect233r1:(LibOrgBouncycastleAsn1X9X9ECParametersHolder *)value;

+ (LibOrgBouncycastleAsn1X9X9ECParametersHolder *)sect239k1;

+ (void)setSect239k1:(LibOrgBouncycastleAsn1X9X9ECParametersHolder *)value;

+ (LibOrgBouncycastleAsn1X9X9ECParametersHolder *)sect283k1;

+ (void)setSect283k1:(LibOrgBouncycastleAsn1X9X9ECParametersHolder *)value;

+ (LibOrgBouncycastleAsn1X9X9ECParametersHolder *)sect283r1;

+ (void)setSect283r1:(LibOrgBouncycastleAsn1X9X9ECParametersHolder *)value;

+ (LibOrgBouncycastleAsn1X9X9ECParametersHolder *)sect409k1;

+ (void)setSect409k1:(LibOrgBouncycastleAsn1X9X9ECParametersHolder *)value;

+ (LibOrgBouncycastleAsn1X9X9ECParametersHolder *)sect409r1;

+ (void)setSect409r1:(LibOrgBouncycastleAsn1X9X9ECParametersHolder *)value;

+ (LibOrgBouncycastleAsn1X9X9ECParametersHolder *)sect571k1;

+ (void)setSect571k1:(LibOrgBouncycastleAsn1X9X9ECParametersHolder *)value;

+ (LibOrgBouncycastleAsn1X9X9ECParametersHolder *)sect571r1;

+ (void)setSect571r1:(LibOrgBouncycastleAsn1X9X9ECParametersHolder *)value;

+ (LibOrgBouncycastleAsn1X9X9ECParametersHolder *)sm2p256v1;

+ (void)setSm2p256v1:(LibOrgBouncycastleAsn1X9X9ECParametersHolder *)value;

+ (JavaUtilHashtable *)nameToCurve;

+ (JavaUtilHashtable *)nameToOID;

+ (JavaUtilHashtable *)oidToCurve;

+ (JavaUtilHashtable *)oidToName;

#pragma mark Public

- (instancetype __nonnull)init;

+ (LibOrgBouncycastleAsn1X9X9ECParameters *)getByNameWithNSString:(NSString *)name;

+ (LibOrgBouncycastleAsn1X9X9ECParameters *)getByOIDWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)oid;

+ (NSString *)getNameWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)oid;

+ (id<JavaUtilEnumeration>)getNames;

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)getOIDWithNSString:(NSString *)name;

#pragma mark Package-Private

+ (void)defineCurveWithNSString:(NSString *)name
withLibOrgBouncycastleAsn1X9X9ECParametersHolder:(LibOrgBouncycastleAsn1X9X9ECParametersHolder *)holder;

+ (void)defineCurveAliasWithNSString:(NSString *)name
withLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)oid;

+ (void)defineCurveWithOIDWithNSString:(NSString *)name
withLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)oid
withLibOrgBouncycastleAsn1X9X9ECParametersHolder:(LibOrgBouncycastleAsn1X9X9ECParametersHolder *)holder;

@end

J2OBJC_STATIC_INIT(LibOrgBouncycastleCryptoEcCustomNamedCurves)

inline LibOrgBouncycastleAsn1X9X9ECParametersHolder *LibOrgBouncycastleCryptoEcCustomNamedCurves_get_curve25519(void);
inline LibOrgBouncycastleAsn1X9X9ECParametersHolder *LibOrgBouncycastleCryptoEcCustomNamedCurves_set_curve25519(LibOrgBouncycastleAsn1X9X9ECParametersHolder *value);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT LibOrgBouncycastleAsn1X9X9ECParametersHolder *LibOrgBouncycastleCryptoEcCustomNamedCurves_curve25519;
J2OBJC_STATIC_FIELD_OBJ(LibOrgBouncycastleCryptoEcCustomNamedCurves, curve25519, LibOrgBouncycastleAsn1X9X9ECParametersHolder *)

inline LibOrgBouncycastleAsn1X9X9ECParametersHolder *LibOrgBouncycastleCryptoEcCustomNamedCurves_get_secp128r1(void);
inline LibOrgBouncycastleAsn1X9X9ECParametersHolder *LibOrgBouncycastleCryptoEcCustomNamedCurves_set_secp128r1(LibOrgBouncycastleAsn1X9X9ECParametersHolder *value);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT LibOrgBouncycastleAsn1X9X9ECParametersHolder *LibOrgBouncycastleCryptoEcCustomNamedCurves_secp128r1;
J2OBJC_STATIC_FIELD_OBJ(LibOrgBouncycastleCryptoEcCustomNamedCurves, secp128r1, LibOrgBouncycastleAsn1X9X9ECParametersHolder *)

inline LibOrgBouncycastleAsn1X9X9ECParametersHolder *LibOrgBouncycastleCryptoEcCustomNamedCurves_get_secp160k1(void);
inline LibOrgBouncycastleAsn1X9X9ECParametersHolder *LibOrgBouncycastleCryptoEcCustomNamedCurves_set_secp160k1(LibOrgBouncycastleAsn1X9X9ECParametersHolder *value);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT LibOrgBouncycastleAsn1X9X9ECParametersHolder *LibOrgBouncycastleCryptoEcCustomNamedCurves_secp160k1;
J2OBJC_STATIC_FIELD_OBJ(LibOrgBouncycastleCryptoEcCustomNamedCurves, secp160k1, LibOrgBouncycastleAsn1X9X9ECParametersHolder *)

inline LibOrgBouncycastleAsn1X9X9ECParametersHolder *LibOrgBouncycastleCryptoEcCustomNamedCurves_get_secp160r1(void);
inline LibOrgBouncycastleAsn1X9X9ECParametersHolder *LibOrgBouncycastleCryptoEcCustomNamedCurves_set_secp160r1(LibOrgBouncycastleAsn1X9X9ECParametersHolder *value);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT LibOrgBouncycastleAsn1X9X9ECParametersHolder *LibOrgBouncycastleCryptoEcCustomNamedCurves_secp160r1;
J2OBJC_STATIC_FIELD_OBJ(LibOrgBouncycastleCryptoEcCustomNamedCurves, secp160r1, LibOrgBouncycastleAsn1X9X9ECParametersHolder *)

inline LibOrgBouncycastleAsn1X9X9ECParametersHolder *LibOrgBouncycastleCryptoEcCustomNamedCurves_get_secp160r2(void);
inline LibOrgBouncycastleAsn1X9X9ECParametersHolder *LibOrgBouncycastleCryptoEcCustomNamedCurves_set_secp160r2(LibOrgBouncycastleAsn1X9X9ECParametersHolder *value);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT LibOrgBouncycastleAsn1X9X9ECParametersHolder *LibOrgBouncycastleCryptoEcCustomNamedCurves_secp160r2;
J2OBJC_STATIC_FIELD_OBJ(LibOrgBouncycastleCryptoEcCustomNamedCurves, secp160r2, LibOrgBouncycastleAsn1X9X9ECParametersHolder *)

inline LibOrgBouncycastleAsn1X9X9ECParametersHolder *LibOrgBouncycastleCryptoEcCustomNamedCurves_get_secp192k1(void);
inline LibOrgBouncycastleAsn1X9X9ECParametersHolder *LibOrgBouncycastleCryptoEcCustomNamedCurves_set_secp192k1(LibOrgBouncycastleAsn1X9X9ECParametersHolder *value);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT LibOrgBouncycastleAsn1X9X9ECParametersHolder *LibOrgBouncycastleCryptoEcCustomNamedCurves_secp192k1;
J2OBJC_STATIC_FIELD_OBJ(LibOrgBouncycastleCryptoEcCustomNamedCurves, secp192k1, LibOrgBouncycastleAsn1X9X9ECParametersHolder *)

inline LibOrgBouncycastleAsn1X9X9ECParametersHolder *LibOrgBouncycastleCryptoEcCustomNamedCurves_get_secp192r1(void);
inline LibOrgBouncycastleAsn1X9X9ECParametersHolder *LibOrgBouncycastleCryptoEcCustomNamedCurves_set_secp192r1(LibOrgBouncycastleAsn1X9X9ECParametersHolder *value);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT LibOrgBouncycastleAsn1X9X9ECParametersHolder *LibOrgBouncycastleCryptoEcCustomNamedCurves_secp192r1;
J2OBJC_STATIC_FIELD_OBJ(LibOrgBouncycastleCryptoEcCustomNamedCurves, secp192r1, LibOrgBouncycastleAsn1X9X9ECParametersHolder *)

inline LibOrgBouncycastleAsn1X9X9ECParametersHolder *LibOrgBouncycastleCryptoEcCustomNamedCurves_get_secp224k1(void);
inline LibOrgBouncycastleAsn1X9X9ECParametersHolder *LibOrgBouncycastleCryptoEcCustomNamedCurves_set_secp224k1(LibOrgBouncycastleAsn1X9X9ECParametersHolder *value);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT LibOrgBouncycastleAsn1X9X9ECParametersHolder *LibOrgBouncycastleCryptoEcCustomNamedCurves_secp224k1;
J2OBJC_STATIC_FIELD_OBJ(LibOrgBouncycastleCryptoEcCustomNamedCurves, secp224k1, LibOrgBouncycastleAsn1X9X9ECParametersHolder *)

inline LibOrgBouncycastleAsn1X9X9ECParametersHolder *LibOrgBouncycastleCryptoEcCustomNamedCurves_get_secp224r1(void);
inline LibOrgBouncycastleAsn1X9X9ECParametersHolder *LibOrgBouncycastleCryptoEcCustomNamedCurves_set_secp224r1(LibOrgBouncycastleAsn1X9X9ECParametersHolder *value);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT LibOrgBouncycastleAsn1X9X9ECParametersHolder *LibOrgBouncycastleCryptoEcCustomNamedCurves_secp224r1;
J2OBJC_STATIC_FIELD_OBJ(LibOrgBouncycastleCryptoEcCustomNamedCurves, secp224r1, LibOrgBouncycastleAsn1X9X9ECParametersHolder *)

inline LibOrgBouncycastleAsn1X9X9ECParametersHolder *LibOrgBouncycastleCryptoEcCustomNamedCurves_get_secp256k1(void);
inline LibOrgBouncycastleAsn1X9X9ECParametersHolder *LibOrgBouncycastleCryptoEcCustomNamedCurves_set_secp256k1(LibOrgBouncycastleAsn1X9X9ECParametersHolder *value);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT LibOrgBouncycastleAsn1X9X9ECParametersHolder *LibOrgBouncycastleCryptoEcCustomNamedCurves_secp256k1;
J2OBJC_STATIC_FIELD_OBJ(LibOrgBouncycastleCryptoEcCustomNamedCurves, secp256k1, LibOrgBouncycastleAsn1X9X9ECParametersHolder *)

inline LibOrgBouncycastleAsn1X9X9ECParametersHolder *LibOrgBouncycastleCryptoEcCustomNamedCurves_get_secp256r1(void);
inline LibOrgBouncycastleAsn1X9X9ECParametersHolder *LibOrgBouncycastleCryptoEcCustomNamedCurves_set_secp256r1(LibOrgBouncycastleAsn1X9X9ECParametersHolder *value);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT LibOrgBouncycastleAsn1X9X9ECParametersHolder *LibOrgBouncycastleCryptoEcCustomNamedCurves_secp256r1;
J2OBJC_STATIC_FIELD_OBJ(LibOrgBouncycastleCryptoEcCustomNamedCurves, secp256r1, LibOrgBouncycastleAsn1X9X9ECParametersHolder *)

inline LibOrgBouncycastleAsn1X9X9ECParametersHolder *LibOrgBouncycastleCryptoEcCustomNamedCurves_get_secp384r1(void);
inline LibOrgBouncycastleAsn1X9X9ECParametersHolder *LibOrgBouncycastleCryptoEcCustomNamedCurves_set_secp384r1(LibOrgBouncycastleAsn1X9X9ECParametersHolder *value);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT LibOrgBouncycastleAsn1X9X9ECParametersHolder *LibOrgBouncycastleCryptoEcCustomNamedCurves_secp384r1;
J2OBJC_STATIC_FIELD_OBJ(LibOrgBouncycastleCryptoEcCustomNamedCurves, secp384r1, LibOrgBouncycastleAsn1X9X9ECParametersHolder *)

inline LibOrgBouncycastleAsn1X9X9ECParametersHolder *LibOrgBouncycastleCryptoEcCustomNamedCurves_get_secp521r1(void);
inline LibOrgBouncycastleAsn1X9X9ECParametersHolder *LibOrgBouncycastleCryptoEcCustomNamedCurves_set_secp521r1(LibOrgBouncycastleAsn1X9X9ECParametersHolder *value);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT LibOrgBouncycastleAsn1X9X9ECParametersHolder *LibOrgBouncycastleCryptoEcCustomNamedCurves_secp521r1;
J2OBJC_STATIC_FIELD_OBJ(LibOrgBouncycastleCryptoEcCustomNamedCurves, secp521r1, LibOrgBouncycastleAsn1X9X9ECParametersHolder *)

inline LibOrgBouncycastleAsn1X9X9ECParametersHolder *LibOrgBouncycastleCryptoEcCustomNamedCurves_get_sect113r1(void);
inline LibOrgBouncycastleAsn1X9X9ECParametersHolder *LibOrgBouncycastleCryptoEcCustomNamedCurves_set_sect113r1(LibOrgBouncycastleAsn1X9X9ECParametersHolder *value);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT LibOrgBouncycastleAsn1X9X9ECParametersHolder *LibOrgBouncycastleCryptoEcCustomNamedCurves_sect113r1;
J2OBJC_STATIC_FIELD_OBJ(LibOrgBouncycastleCryptoEcCustomNamedCurves, sect113r1, LibOrgBouncycastleAsn1X9X9ECParametersHolder *)

inline LibOrgBouncycastleAsn1X9X9ECParametersHolder *LibOrgBouncycastleCryptoEcCustomNamedCurves_get_sect113r2(void);
inline LibOrgBouncycastleAsn1X9X9ECParametersHolder *LibOrgBouncycastleCryptoEcCustomNamedCurves_set_sect113r2(LibOrgBouncycastleAsn1X9X9ECParametersHolder *value);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT LibOrgBouncycastleAsn1X9X9ECParametersHolder *LibOrgBouncycastleCryptoEcCustomNamedCurves_sect113r2;
J2OBJC_STATIC_FIELD_OBJ(LibOrgBouncycastleCryptoEcCustomNamedCurves, sect113r2, LibOrgBouncycastleAsn1X9X9ECParametersHolder *)

inline LibOrgBouncycastleAsn1X9X9ECParametersHolder *LibOrgBouncycastleCryptoEcCustomNamedCurves_get_sect131r1(void);
inline LibOrgBouncycastleAsn1X9X9ECParametersHolder *LibOrgBouncycastleCryptoEcCustomNamedCurves_set_sect131r1(LibOrgBouncycastleAsn1X9X9ECParametersHolder *value);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT LibOrgBouncycastleAsn1X9X9ECParametersHolder *LibOrgBouncycastleCryptoEcCustomNamedCurves_sect131r1;
J2OBJC_STATIC_FIELD_OBJ(LibOrgBouncycastleCryptoEcCustomNamedCurves, sect131r1, LibOrgBouncycastleAsn1X9X9ECParametersHolder *)

inline LibOrgBouncycastleAsn1X9X9ECParametersHolder *LibOrgBouncycastleCryptoEcCustomNamedCurves_get_sect131r2(void);
inline LibOrgBouncycastleAsn1X9X9ECParametersHolder *LibOrgBouncycastleCryptoEcCustomNamedCurves_set_sect131r2(LibOrgBouncycastleAsn1X9X9ECParametersHolder *value);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT LibOrgBouncycastleAsn1X9X9ECParametersHolder *LibOrgBouncycastleCryptoEcCustomNamedCurves_sect131r2;
J2OBJC_STATIC_FIELD_OBJ(LibOrgBouncycastleCryptoEcCustomNamedCurves, sect131r2, LibOrgBouncycastleAsn1X9X9ECParametersHolder *)

inline LibOrgBouncycastleAsn1X9X9ECParametersHolder *LibOrgBouncycastleCryptoEcCustomNamedCurves_get_sect163k1(void);
inline LibOrgBouncycastleAsn1X9X9ECParametersHolder *LibOrgBouncycastleCryptoEcCustomNamedCurves_set_sect163k1(LibOrgBouncycastleAsn1X9X9ECParametersHolder *value);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT LibOrgBouncycastleAsn1X9X9ECParametersHolder *LibOrgBouncycastleCryptoEcCustomNamedCurves_sect163k1;
J2OBJC_STATIC_FIELD_OBJ(LibOrgBouncycastleCryptoEcCustomNamedCurves, sect163k1, LibOrgBouncycastleAsn1X9X9ECParametersHolder *)

inline LibOrgBouncycastleAsn1X9X9ECParametersHolder *LibOrgBouncycastleCryptoEcCustomNamedCurves_get_sect163r1(void);
inline LibOrgBouncycastleAsn1X9X9ECParametersHolder *LibOrgBouncycastleCryptoEcCustomNamedCurves_set_sect163r1(LibOrgBouncycastleAsn1X9X9ECParametersHolder *value);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT LibOrgBouncycastleAsn1X9X9ECParametersHolder *LibOrgBouncycastleCryptoEcCustomNamedCurves_sect163r1;
J2OBJC_STATIC_FIELD_OBJ(LibOrgBouncycastleCryptoEcCustomNamedCurves, sect163r1, LibOrgBouncycastleAsn1X9X9ECParametersHolder *)

inline LibOrgBouncycastleAsn1X9X9ECParametersHolder *LibOrgBouncycastleCryptoEcCustomNamedCurves_get_sect163r2(void);
inline LibOrgBouncycastleAsn1X9X9ECParametersHolder *LibOrgBouncycastleCryptoEcCustomNamedCurves_set_sect163r2(LibOrgBouncycastleAsn1X9X9ECParametersHolder *value);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT LibOrgBouncycastleAsn1X9X9ECParametersHolder *LibOrgBouncycastleCryptoEcCustomNamedCurves_sect163r2;
J2OBJC_STATIC_FIELD_OBJ(LibOrgBouncycastleCryptoEcCustomNamedCurves, sect163r2, LibOrgBouncycastleAsn1X9X9ECParametersHolder *)

inline LibOrgBouncycastleAsn1X9X9ECParametersHolder *LibOrgBouncycastleCryptoEcCustomNamedCurves_get_sect193r1(void);
inline LibOrgBouncycastleAsn1X9X9ECParametersHolder *LibOrgBouncycastleCryptoEcCustomNamedCurves_set_sect193r1(LibOrgBouncycastleAsn1X9X9ECParametersHolder *value);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT LibOrgBouncycastleAsn1X9X9ECParametersHolder *LibOrgBouncycastleCryptoEcCustomNamedCurves_sect193r1;
J2OBJC_STATIC_FIELD_OBJ(LibOrgBouncycastleCryptoEcCustomNamedCurves, sect193r1, LibOrgBouncycastleAsn1X9X9ECParametersHolder *)

inline LibOrgBouncycastleAsn1X9X9ECParametersHolder *LibOrgBouncycastleCryptoEcCustomNamedCurves_get_sect193r2(void);
inline LibOrgBouncycastleAsn1X9X9ECParametersHolder *LibOrgBouncycastleCryptoEcCustomNamedCurves_set_sect193r2(LibOrgBouncycastleAsn1X9X9ECParametersHolder *value);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT LibOrgBouncycastleAsn1X9X9ECParametersHolder *LibOrgBouncycastleCryptoEcCustomNamedCurves_sect193r2;
J2OBJC_STATIC_FIELD_OBJ(LibOrgBouncycastleCryptoEcCustomNamedCurves, sect193r2, LibOrgBouncycastleAsn1X9X9ECParametersHolder *)

inline LibOrgBouncycastleAsn1X9X9ECParametersHolder *LibOrgBouncycastleCryptoEcCustomNamedCurves_get_sect233k1(void);
inline LibOrgBouncycastleAsn1X9X9ECParametersHolder *LibOrgBouncycastleCryptoEcCustomNamedCurves_set_sect233k1(LibOrgBouncycastleAsn1X9X9ECParametersHolder *value);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT LibOrgBouncycastleAsn1X9X9ECParametersHolder *LibOrgBouncycastleCryptoEcCustomNamedCurves_sect233k1;
J2OBJC_STATIC_FIELD_OBJ(LibOrgBouncycastleCryptoEcCustomNamedCurves, sect233k1, LibOrgBouncycastleAsn1X9X9ECParametersHolder *)

inline LibOrgBouncycastleAsn1X9X9ECParametersHolder *LibOrgBouncycastleCryptoEcCustomNamedCurves_get_sect233r1(void);
inline LibOrgBouncycastleAsn1X9X9ECParametersHolder *LibOrgBouncycastleCryptoEcCustomNamedCurves_set_sect233r1(LibOrgBouncycastleAsn1X9X9ECParametersHolder *value);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT LibOrgBouncycastleAsn1X9X9ECParametersHolder *LibOrgBouncycastleCryptoEcCustomNamedCurves_sect233r1;
J2OBJC_STATIC_FIELD_OBJ(LibOrgBouncycastleCryptoEcCustomNamedCurves, sect233r1, LibOrgBouncycastleAsn1X9X9ECParametersHolder *)

inline LibOrgBouncycastleAsn1X9X9ECParametersHolder *LibOrgBouncycastleCryptoEcCustomNamedCurves_get_sect239k1(void);
inline LibOrgBouncycastleAsn1X9X9ECParametersHolder *LibOrgBouncycastleCryptoEcCustomNamedCurves_set_sect239k1(LibOrgBouncycastleAsn1X9X9ECParametersHolder *value);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT LibOrgBouncycastleAsn1X9X9ECParametersHolder *LibOrgBouncycastleCryptoEcCustomNamedCurves_sect239k1;
J2OBJC_STATIC_FIELD_OBJ(LibOrgBouncycastleCryptoEcCustomNamedCurves, sect239k1, LibOrgBouncycastleAsn1X9X9ECParametersHolder *)

inline LibOrgBouncycastleAsn1X9X9ECParametersHolder *LibOrgBouncycastleCryptoEcCustomNamedCurves_get_sect283k1(void);
inline LibOrgBouncycastleAsn1X9X9ECParametersHolder *LibOrgBouncycastleCryptoEcCustomNamedCurves_set_sect283k1(LibOrgBouncycastleAsn1X9X9ECParametersHolder *value);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT LibOrgBouncycastleAsn1X9X9ECParametersHolder *LibOrgBouncycastleCryptoEcCustomNamedCurves_sect283k1;
J2OBJC_STATIC_FIELD_OBJ(LibOrgBouncycastleCryptoEcCustomNamedCurves, sect283k1, LibOrgBouncycastleAsn1X9X9ECParametersHolder *)

inline LibOrgBouncycastleAsn1X9X9ECParametersHolder *LibOrgBouncycastleCryptoEcCustomNamedCurves_get_sect283r1(void);
inline LibOrgBouncycastleAsn1X9X9ECParametersHolder *LibOrgBouncycastleCryptoEcCustomNamedCurves_set_sect283r1(LibOrgBouncycastleAsn1X9X9ECParametersHolder *value);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT LibOrgBouncycastleAsn1X9X9ECParametersHolder *LibOrgBouncycastleCryptoEcCustomNamedCurves_sect283r1;
J2OBJC_STATIC_FIELD_OBJ(LibOrgBouncycastleCryptoEcCustomNamedCurves, sect283r1, LibOrgBouncycastleAsn1X9X9ECParametersHolder *)

inline LibOrgBouncycastleAsn1X9X9ECParametersHolder *LibOrgBouncycastleCryptoEcCustomNamedCurves_get_sect409k1(void);
inline LibOrgBouncycastleAsn1X9X9ECParametersHolder *LibOrgBouncycastleCryptoEcCustomNamedCurves_set_sect409k1(LibOrgBouncycastleAsn1X9X9ECParametersHolder *value);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT LibOrgBouncycastleAsn1X9X9ECParametersHolder *LibOrgBouncycastleCryptoEcCustomNamedCurves_sect409k1;
J2OBJC_STATIC_FIELD_OBJ(LibOrgBouncycastleCryptoEcCustomNamedCurves, sect409k1, LibOrgBouncycastleAsn1X9X9ECParametersHolder *)

inline LibOrgBouncycastleAsn1X9X9ECParametersHolder *LibOrgBouncycastleCryptoEcCustomNamedCurves_get_sect409r1(void);
inline LibOrgBouncycastleAsn1X9X9ECParametersHolder *LibOrgBouncycastleCryptoEcCustomNamedCurves_set_sect409r1(LibOrgBouncycastleAsn1X9X9ECParametersHolder *value);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT LibOrgBouncycastleAsn1X9X9ECParametersHolder *LibOrgBouncycastleCryptoEcCustomNamedCurves_sect409r1;
J2OBJC_STATIC_FIELD_OBJ(LibOrgBouncycastleCryptoEcCustomNamedCurves, sect409r1, LibOrgBouncycastleAsn1X9X9ECParametersHolder *)

inline LibOrgBouncycastleAsn1X9X9ECParametersHolder *LibOrgBouncycastleCryptoEcCustomNamedCurves_get_sect571k1(void);
inline LibOrgBouncycastleAsn1X9X9ECParametersHolder *LibOrgBouncycastleCryptoEcCustomNamedCurves_set_sect571k1(LibOrgBouncycastleAsn1X9X9ECParametersHolder *value);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT LibOrgBouncycastleAsn1X9X9ECParametersHolder *LibOrgBouncycastleCryptoEcCustomNamedCurves_sect571k1;
J2OBJC_STATIC_FIELD_OBJ(LibOrgBouncycastleCryptoEcCustomNamedCurves, sect571k1, LibOrgBouncycastleAsn1X9X9ECParametersHolder *)

inline LibOrgBouncycastleAsn1X9X9ECParametersHolder *LibOrgBouncycastleCryptoEcCustomNamedCurves_get_sect571r1(void);
inline LibOrgBouncycastleAsn1X9X9ECParametersHolder *LibOrgBouncycastleCryptoEcCustomNamedCurves_set_sect571r1(LibOrgBouncycastleAsn1X9X9ECParametersHolder *value);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT LibOrgBouncycastleAsn1X9X9ECParametersHolder *LibOrgBouncycastleCryptoEcCustomNamedCurves_sect571r1;
J2OBJC_STATIC_FIELD_OBJ(LibOrgBouncycastleCryptoEcCustomNamedCurves, sect571r1, LibOrgBouncycastleAsn1X9X9ECParametersHolder *)

inline LibOrgBouncycastleAsn1X9X9ECParametersHolder *LibOrgBouncycastleCryptoEcCustomNamedCurves_get_sm2p256v1(void);
inline LibOrgBouncycastleAsn1X9X9ECParametersHolder *LibOrgBouncycastleCryptoEcCustomNamedCurves_set_sm2p256v1(LibOrgBouncycastleAsn1X9X9ECParametersHolder *value);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT LibOrgBouncycastleAsn1X9X9ECParametersHolder *LibOrgBouncycastleCryptoEcCustomNamedCurves_sm2p256v1;
J2OBJC_STATIC_FIELD_OBJ(LibOrgBouncycastleCryptoEcCustomNamedCurves, sm2p256v1, LibOrgBouncycastleAsn1X9X9ECParametersHolder *)

inline JavaUtilHashtable *LibOrgBouncycastleCryptoEcCustomNamedCurves_get_nameToCurve(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT JavaUtilHashtable *LibOrgBouncycastleCryptoEcCustomNamedCurves_nameToCurve;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleCryptoEcCustomNamedCurves, nameToCurve, JavaUtilHashtable *)

inline JavaUtilHashtable *LibOrgBouncycastleCryptoEcCustomNamedCurves_get_nameToOID(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT JavaUtilHashtable *LibOrgBouncycastleCryptoEcCustomNamedCurves_nameToOID;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleCryptoEcCustomNamedCurves, nameToOID, JavaUtilHashtable *)

inline JavaUtilHashtable *LibOrgBouncycastleCryptoEcCustomNamedCurves_get_oidToCurve(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT JavaUtilHashtable *LibOrgBouncycastleCryptoEcCustomNamedCurves_oidToCurve;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleCryptoEcCustomNamedCurves, oidToCurve, JavaUtilHashtable *)

inline JavaUtilHashtable *LibOrgBouncycastleCryptoEcCustomNamedCurves_get_oidToName(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT JavaUtilHashtable *LibOrgBouncycastleCryptoEcCustomNamedCurves_oidToName;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleCryptoEcCustomNamedCurves, oidToName, JavaUtilHashtable *)

inline JavaUtilVector *LibOrgBouncycastleCryptoEcCustomNamedCurves_get_names(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT JavaUtilVector *LibOrgBouncycastleCryptoEcCustomNamedCurves_names;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleCryptoEcCustomNamedCurves, names, JavaUtilVector *)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoEcCustomNamedCurves_init(LibOrgBouncycastleCryptoEcCustomNamedCurves *self);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoEcCustomNamedCurves *new_LibOrgBouncycastleCryptoEcCustomNamedCurves_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoEcCustomNamedCurves *create_LibOrgBouncycastleCryptoEcCustomNamedCurves_init(void);

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoEcCustomNamedCurves_defineCurveWithNSString_withLibOrgBouncycastleAsn1X9X9ECParametersHolder_(NSString *name, LibOrgBouncycastleAsn1X9X9ECParametersHolder *holder);

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoEcCustomNamedCurves_defineCurveWithOIDWithNSString_withLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1X9X9ECParametersHolder_(NSString *name, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *oid, LibOrgBouncycastleAsn1X9X9ECParametersHolder *holder);

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoEcCustomNamedCurves_defineCurveAliasWithNSString_withLibOrgBouncycastleAsn1ASN1ObjectIdentifier_(NSString *name, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *oid);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1X9X9ECParameters *LibOrgBouncycastleCryptoEcCustomNamedCurves_getByNameWithNSString_(NSString *name);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1X9X9ECParameters *LibOrgBouncycastleCryptoEcCustomNamedCurves_getByOIDWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *oid);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleCryptoEcCustomNamedCurves_getOIDWithNSString_(NSString *name);

FOUNDATION_EXPORT NSString *LibOrgBouncycastleCryptoEcCustomNamedCurves_getNameWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *oid);

FOUNDATION_EXPORT id<JavaUtilEnumeration> LibOrgBouncycastleCryptoEcCustomNamedCurves_getNames(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoEcCustomNamedCurves)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // CustomNamedCurves_H