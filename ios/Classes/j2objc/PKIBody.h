//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/cmp/PKIBody.java
//

#ifndef PKIBody_H
#define PKIBody_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ASN1Choice.h"
#include "ASN1Object.h"
#include "J2ObjC_header.h"

@class LibOrgBouncycastleAsn1ASN1Primitive;
@protocol LibOrgBouncycastleAsn1ASN1Encodable;

@interface LibOrgBouncycastleAsn1CmpPKIBody : LibOrgBouncycastleAsn1ASN1Object < LibOrgBouncycastleAsn1ASN1Choice >
@property (readonly, class) jint TYPE_INIT_REQ NS_SWIFT_NAME(TYPE_INIT_REQ);
@property (readonly, class) jint TYPE_INIT_REP NS_SWIFT_NAME(TYPE_INIT_REP);
@property (readonly, class) jint TYPE_CERT_REQ NS_SWIFT_NAME(TYPE_CERT_REQ);
@property (readonly, class) jint TYPE_CERT_REP NS_SWIFT_NAME(TYPE_CERT_REP);
@property (readonly, class) jint TYPE_P10_CERT_REQ NS_SWIFT_NAME(TYPE_P10_CERT_REQ);
@property (readonly, class) jint TYPE_POPO_CHALL NS_SWIFT_NAME(TYPE_POPO_CHALL);
@property (readonly, class) jint TYPE_POPO_REP NS_SWIFT_NAME(TYPE_POPO_REP);
@property (readonly, class) jint TYPE_KEY_UPDATE_REQ NS_SWIFT_NAME(TYPE_KEY_UPDATE_REQ);
@property (readonly, class) jint TYPE_KEY_UPDATE_REP NS_SWIFT_NAME(TYPE_KEY_UPDATE_REP);
@property (readonly, class) jint TYPE_KEY_RECOVERY_REQ NS_SWIFT_NAME(TYPE_KEY_RECOVERY_REQ);
@property (readonly, class) jint TYPE_KEY_RECOVERY_REP NS_SWIFT_NAME(TYPE_KEY_RECOVERY_REP);
@property (readonly, class) jint TYPE_REVOCATION_REQ NS_SWIFT_NAME(TYPE_REVOCATION_REQ);
@property (readonly, class) jint TYPE_REVOCATION_REP NS_SWIFT_NAME(TYPE_REVOCATION_REP);
@property (readonly, class) jint TYPE_CROSS_CERT_REQ NS_SWIFT_NAME(TYPE_CROSS_CERT_REQ);
@property (readonly, class) jint TYPE_CROSS_CERT_REP NS_SWIFT_NAME(TYPE_CROSS_CERT_REP);
@property (readonly, class) jint TYPE_CA_KEY_UPDATE_ANN NS_SWIFT_NAME(TYPE_CA_KEY_UPDATE_ANN);
@property (readonly, class) jint TYPE_CERT_ANN NS_SWIFT_NAME(TYPE_CERT_ANN);
@property (readonly, class) jint TYPE_REVOCATION_ANN NS_SWIFT_NAME(TYPE_REVOCATION_ANN);
@property (readonly, class) jint TYPE_CRL_ANN NS_SWIFT_NAME(TYPE_CRL_ANN);
@property (readonly, class) jint TYPE_CONFIRM NS_SWIFT_NAME(TYPE_CONFIRM);
@property (readonly, class) jint TYPE_NESTED NS_SWIFT_NAME(TYPE_NESTED);
@property (readonly, class) jint TYPE_GEN_MSG NS_SWIFT_NAME(TYPE_GEN_MSG);
@property (readonly, class) jint TYPE_GEN_REP NS_SWIFT_NAME(TYPE_GEN_REP);
@property (readonly, class) jint TYPE_ERROR NS_SWIFT_NAME(TYPE_ERROR);
@property (readonly, class) jint TYPE_CERT_CONFIRM NS_SWIFT_NAME(TYPE_CERT_CONFIRM);
@property (readonly, class) jint TYPE_POLL_REQ NS_SWIFT_NAME(TYPE_POLL_REQ);
@property (readonly, class) jint TYPE_POLL_REP NS_SWIFT_NAME(TYPE_POLL_REP);

+ (jint)TYPE_INIT_REQ;

+ (jint)TYPE_INIT_REP;

+ (jint)TYPE_CERT_REQ;

+ (jint)TYPE_CERT_REP;

+ (jint)TYPE_P10_CERT_REQ;

+ (jint)TYPE_POPO_CHALL;

+ (jint)TYPE_POPO_REP;

+ (jint)TYPE_KEY_UPDATE_REQ;

+ (jint)TYPE_KEY_UPDATE_REP;

+ (jint)TYPE_KEY_RECOVERY_REQ;

+ (jint)TYPE_KEY_RECOVERY_REP;

+ (jint)TYPE_REVOCATION_REQ;

+ (jint)TYPE_REVOCATION_REP;

+ (jint)TYPE_CROSS_CERT_REQ;

+ (jint)TYPE_CROSS_CERT_REP;

+ (jint)TYPE_CA_KEY_UPDATE_ANN;

+ (jint)TYPE_CERT_ANN;

+ (jint)TYPE_REVOCATION_ANN;

+ (jint)TYPE_CRL_ANN;

+ (jint)TYPE_CONFIRM;

+ (jint)TYPE_NESTED;

+ (jint)TYPE_GEN_MSG;

+ (jint)TYPE_GEN_REP;

+ (jint)TYPE_ERROR;

+ (jint)TYPE_CERT_CONFIRM;

+ (jint)TYPE_POLL_REQ;

+ (jint)TYPE_POLL_REP;

#pragma mark Public

- (instancetype __nonnull)initWithInt:(jint)type
withLibOrgBouncycastleAsn1ASN1Encodable:(id<LibOrgBouncycastleAsn1ASN1Encodable>)content;

- (id<LibOrgBouncycastleAsn1ASN1Encodable>)getContent;

+ (LibOrgBouncycastleAsn1CmpPKIBody *)getInstanceWithId:(id)o;

- (jint)getType;

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleAsn1CmpPKIBody)

inline jint LibOrgBouncycastleAsn1CmpPKIBody_get_TYPE_INIT_REQ(void);
#define LibOrgBouncycastleAsn1CmpPKIBody_TYPE_INIT_REQ 0
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleAsn1CmpPKIBody, TYPE_INIT_REQ, jint)

inline jint LibOrgBouncycastleAsn1CmpPKIBody_get_TYPE_INIT_REP(void);
#define LibOrgBouncycastleAsn1CmpPKIBody_TYPE_INIT_REP 1
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleAsn1CmpPKIBody, TYPE_INIT_REP, jint)

inline jint LibOrgBouncycastleAsn1CmpPKIBody_get_TYPE_CERT_REQ(void);
#define LibOrgBouncycastleAsn1CmpPKIBody_TYPE_CERT_REQ 2
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleAsn1CmpPKIBody, TYPE_CERT_REQ, jint)

inline jint LibOrgBouncycastleAsn1CmpPKIBody_get_TYPE_CERT_REP(void);
#define LibOrgBouncycastleAsn1CmpPKIBody_TYPE_CERT_REP 3
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleAsn1CmpPKIBody, TYPE_CERT_REP, jint)

inline jint LibOrgBouncycastleAsn1CmpPKIBody_get_TYPE_P10_CERT_REQ(void);
#define LibOrgBouncycastleAsn1CmpPKIBody_TYPE_P10_CERT_REQ 4
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleAsn1CmpPKIBody, TYPE_P10_CERT_REQ, jint)

inline jint LibOrgBouncycastleAsn1CmpPKIBody_get_TYPE_POPO_CHALL(void);
#define LibOrgBouncycastleAsn1CmpPKIBody_TYPE_POPO_CHALL 5
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleAsn1CmpPKIBody, TYPE_POPO_CHALL, jint)

inline jint LibOrgBouncycastleAsn1CmpPKIBody_get_TYPE_POPO_REP(void);
#define LibOrgBouncycastleAsn1CmpPKIBody_TYPE_POPO_REP 6
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleAsn1CmpPKIBody, TYPE_POPO_REP, jint)

inline jint LibOrgBouncycastleAsn1CmpPKIBody_get_TYPE_KEY_UPDATE_REQ(void);
#define LibOrgBouncycastleAsn1CmpPKIBody_TYPE_KEY_UPDATE_REQ 7
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleAsn1CmpPKIBody, TYPE_KEY_UPDATE_REQ, jint)

inline jint LibOrgBouncycastleAsn1CmpPKIBody_get_TYPE_KEY_UPDATE_REP(void);
#define LibOrgBouncycastleAsn1CmpPKIBody_TYPE_KEY_UPDATE_REP 8
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleAsn1CmpPKIBody, TYPE_KEY_UPDATE_REP, jint)

inline jint LibOrgBouncycastleAsn1CmpPKIBody_get_TYPE_KEY_RECOVERY_REQ(void);
#define LibOrgBouncycastleAsn1CmpPKIBody_TYPE_KEY_RECOVERY_REQ 9
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleAsn1CmpPKIBody, TYPE_KEY_RECOVERY_REQ, jint)

inline jint LibOrgBouncycastleAsn1CmpPKIBody_get_TYPE_KEY_RECOVERY_REP(void);
#define LibOrgBouncycastleAsn1CmpPKIBody_TYPE_KEY_RECOVERY_REP 10
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleAsn1CmpPKIBody, TYPE_KEY_RECOVERY_REP, jint)

inline jint LibOrgBouncycastleAsn1CmpPKIBody_get_TYPE_REVOCATION_REQ(void);
#define LibOrgBouncycastleAsn1CmpPKIBody_TYPE_REVOCATION_REQ 11
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleAsn1CmpPKIBody, TYPE_REVOCATION_REQ, jint)

inline jint LibOrgBouncycastleAsn1CmpPKIBody_get_TYPE_REVOCATION_REP(void);
#define LibOrgBouncycastleAsn1CmpPKIBody_TYPE_REVOCATION_REP 12
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleAsn1CmpPKIBody, TYPE_REVOCATION_REP, jint)

inline jint LibOrgBouncycastleAsn1CmpPKIBody_get_TYPE_CROSS_CERT_REQ(void);
#define LibOrgBouncycastleAsn1CmpPKIBody_TYPE_CROSS_CERT_REQ 13
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleAsn1CmpPKIBody, TYPE_CROSS_CERT_REQ, jint)

inline jint LibOrgBouncycastleAsn1CmpPKIBody_get_TYPE_CROSS_CERT_REP(void);
#define LibOrgBouncycastleAsn1CmpPKIBody_TYPE_CROSS_CERT_REP 14
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleAsn1CmpPKIBody, TYPE_CROSS_CERT_REP, jint)

inline jint LibOrgBouncycastleAsn1CmpPKIBody_get_TYPE_CA_KEY_UPDATE_ANN(void);
#define LibOrgBouncycastleAsn1CmpPKIBody_TYPE_CA_KEY_UPDATE_ANN 15
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleAsn1CmpPKIBody, TYPE_CA_KEY_UPDATE_ANN, jint)

inline jint LibOrgBouncycastleAsn1CmpPKIBody_get_TYPE_CERT_ANN(void);
#define LibOrgBouncycastleAsn1CmpPKIBody_TYPE_CERT_ANN 16
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleAsn1CmpPKIBody, TYPE_CERT_ANN, jint)

inline jint LibOrgBouncycastleAsn1CmpPKIBody_get_TYPE_REVOCATION_ANN(void);
#define LibOrgBouncycastleAsn1CmpPKIBody_TYPE_REVOCATION_ANN 17
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleAsn1CmpPKIBody, TYPE_REVOCATION_ANN, jint)

inline jint LibOrgBouncycastleAsn1CmpPKIBody_get_TYPE_CRL_ANN(void);
#define LibOrgBouncycastleAsn1CmpPKIBody_TYPE_CRL_ANN 18
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleAsn1CmpPKIBody, TYPE_CRL_ANN, jint)

inline jint LibOrgBouncycastleAsn1CmpPKIBody_get_TYPE_CONFIRM(void);
#define LibOrgBouncycastleAsn1CmpPKIBody_TYPE_CONFIRM 19
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleAsn1CmpPKIBody, TYPE_CONFIRM, jint)

inline jint LibOrgBouncycastleAsn1CmpPKIBody_get_TYPE_NESTED(void);
#define LibOrgBouncycastleAsn1CmpPKIBody_TYPE_NESTED 20
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleAsn1CmpPKIBody, TYPE_NESTED, jint)

inline jint LibOrgBouncycastleAsn1CmpPKIBody_get_TYPE_GEN_MSG(void);
#define LibOrgBouncycastleAsn1CmpPKIBody_TYPE_GEN_MSG 21
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleAsn1CmpPKIBody, TYPE_GEN_MSG, jint)

inline jint LibOrgBouncycastleAsn1CmpPKIBody_get_TYPE_GEN_REP(void);
#define LibOrgBouncycastleAsn1CmpPKIBody_TYPE_GEN_REP 22
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleAsn1CmpPKIBody, TYPE_GEN_REP, jint)

inline jint LibOrgBouncycastleAsn1CmpPKIBody_get_TYPE_ERROR(void);
#define LibOrgBouncycastleAsn1CmpPKIBody_TYPE_ERROR 23
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleAsn1CmpPKIBody, TYPE_ERROR, jint)

inline jint LibOrgBouncycastleAsn1CmpPKIBody_get_TYPE_CERT_CONFIRM(void);
#define LibOrgBouncycastleAsn1CmpPKIBody_TYPE_CERT_CONFIRM 24
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleAsn1CmpPKIBody, TYPE_CERT_CONFIRM, jint)

inline jint LibOrgBouncycastleAsn1CmpPKIBody_get_TYPE_POLL_REQ(void);
#define LibOrgBouncycastleAsn1CmpPKIBody_TYPE_POLL_REQ 25
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleAsn1CmpPKIBody, TYPE_POLL_REQ, jint)

inline jint LibOrgBouncycastleAsn1CmpPKIBody_get_TYPE_POLL_REP(void);
#define LibOrgBouncycastleAsn1CmpPKIBody_TYPE_POLL_REP 26
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleAsn1CmpPKIBody, TYPE_POLL_REP, jint)

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CmpPKIBody *LibOrgBouncycastleAsn1CmpPKIBody_getInstanceWithId_(id o);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1CmpPKIBody_initWithInt_withLibOrgBouncycastleAsn1ASN1Encodable_(LibOrgBouncycastleAsn1CmpPKIBody *self, jint type, id<LibOrgBouncycastleAsn1ASN1Encodable> content);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CmpPKIBody *new_LibOrgBouncycastleAsn1CmpPKIBody_initWithInt_withLibOrgBouncycastleAsn1ASN1Encodable_(jint type, id<LibOrgBouncycastleAsn1ASN1Encodable> content) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CmpPKIBody *create_LibOrgBouncycastleAsn1CmpPKIBody_initWithInt_withLibOrgBouncycastleAsn1ASN1Encodable_(jint type, id<LibOrgBouncycastleAsn1ASN1Encodable> content);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1CmpPKIBody)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // PKIBody_H