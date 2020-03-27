//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/isismtt/x509/ProfessionInfo.java
//

#ifndef ProfessionInfo_H
#define ProfessionInfo_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ASN1Object.h"
#include "J2ObjC_header.h"

@class IOSObjectArray;
@class LibOrgBouncycastleAsn1ASN1ObjectIdentifier;
@class LibOrgBouncycastleAsn1ASN1OctetString;
@class LibOrgBouncycastleAsn1ASN1Primitive;
@class LibOrgBouncycastleAsn1IsismttX509NamingAuthority;

@interface LibOrgBouncycastleAsn1IsismttX509ProfessionInfo : LibOrgBouncycastleAsn1ASN1Object
@property (readonly, class) LibOrgBouncycastleAsn1ASN1ObjectIdentifier *Rechtsanwltin NS_SWIFT_NAME(Rechtsanwltin);
@property (readonly, class) LibOrgBouncycastleAsn1ASN1ObjectIdentifier *Rechtsanwalt NS_SWIFT_NAME(Rechtsanwalt);
@property (readonly, class) LibOrgBouncycastleAsn1ASN1ObjectIdentifier *Rechtsbeistand NS_SWIFT_NAME(Rechtsbeistand);
@property (readonly, class) LibOrgBouncycastleAsn1ASN1ObjectIdentifier *Steuerberaterin NS_SWIFT_NAME(Steuerberaterin);
@property (readonly, class) LibOrgBouncycastleAsn1ASN1ObjectIdentifier *Steuerberater NS_SWIFT_NAME(Steuerberater);
@property (readonly, class) LibOrgBouncycastleAsn1ASN1ObjectIdentifier *Steuerbevollmchtigte NS_SWIFT_NAME(Steuerbevollmchtigte);
@property (readonly, class) LibOrgBouncycastleAsn1ASN1ObjectIdentifier *Steuerbevollmchtigter NS_SWIFT_NAME(Steuerbevollmchtigter);
@property (readonly, class) LibOrgBouncycastleAsn1ASN1ObjectIdentifier *Notarin NS_SWIFT_NAME(Notarin);
@property (readonly, class) LibOrgBouncycastleAsn1ASN1ObjectIdentifier *Notar NS_SWIFT_NAME(Notar);
@property (readonly, class) LibOrgBouncycastleAsn1ASN1ObjectIdentifier *Notarvertreterin NS_SWIFT_NAME(Notarvertreterin);
@property (readonly, class) LibOrgBouncycastleAsn1ASN1ObjectIdentifier *Notarvertreter NS_SWIFT_NAME(Notarvertreter);
@property (readonly, class) LibOrgBouncycastleAsn1ASN1ObjectIdentifier *Notariatsverwalterin NS_SWIFT_NAME(Notariatsverwalterin);
@property (readonly, class) LibOrgBouncycastleAsn1ASN1ObjectIdentifier *Notariatsverwalter NS_SWIFT_NAME(Notariatsverwalter);
@property (readonly, class) LibOrgBouncycastleAsn1ASN1ObjectIdentifier *Wirtschaftsprferin NS_SWIFT_NAME(Wirtschaftsprferin);
@property (readonly, class) LibOrgBouncycastleAsn1ASN1ObjectIdentifier *Wirtschaftsprfer NS_SWIFT_NAME(Wirtschaftsprfer);
@property (readonly, class) LibOrgBouncycastleAsn1ASN1ObjectIdentifier *VereidigteBuchprferin NS_SWIFT_NAME(VereidigteBuchprferin);
@property (readonly, class) LibOrgBouncycastleAsn1ASN1ObjectIdentifier *VereidigterBuchprfer NS_SWIFT_NAME(VereidigterBuchprfer);
@property (readonly, class) LibOrgBouncycastleAsn1ASN1ObjectIdentifier *Patentanwltin NS_SWIFT_NAME(Patentanwltin);
@property (readonly, class) LibOrgBouncycastleAsn1ASN1ObjectIdentifier *Patentanwalt NS_SWIFT_NAME(Patentanwalt);

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)Rechtsanwltin;

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)Rechtsanwalt;

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)Rechtsbeistand;

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)Steuerberaterin;

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)Steuerberater;

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)Steuerbevollmchtigte;

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)Steuerbevollmchtigter;

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)Notarin;

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)Notar;

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)Notarvertreterin;

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)Notarvertreter;

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)Notariatsverwalterin;

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)Notariatsverwalter;

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)Wirtschaftsprferin;

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)Wirtschaftsprfer;

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)VereidigteBuchprferin;

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)VereidigterBuchprfer;

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)Patentanwltin;

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)Patentanwalt;

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1IsismttX509NamingAuthority:(LibOrgBouncycastleAsn1IsismttX509NamingAuthority *)namingAuthority
                                withLibOrgBouncycastleAsn1X500DirectoryStringArray:(IOSObjectArray *)professionItems
                               withLibOrgBouncycastleAsn1ASN1ObjectIdentifierArray:(IOSObjectArray *)professionOIDs
                                                                      withNSString:(NSString *)registrationNumber
                                         withLibOrgBouncycastleAsn1ASN1OctetString:(LibOrgBouncycastleAsn1ASN1OctetString *)addProfessionInfo;

- (LibOrgBouncycastleAsn1ASN1OctetString *)getAddProfessionInfo;

+ (LibOrgBouncycastleAsn1IsismttX509ProfessionInfo *)getInstanceWithId:(id)obj;

- (LibOrgBouncycastleAsn1IsismttX509NamingAuthority *)getNamingAuthority;

- (IOSObjectArray *)getProfessionItems;

- (IOSObjectArray *)getProfessionOIDs;

- (NSString *)getRegistrationNumber;

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_STATIC_INIT(LibOrgBouncycastleAsn1IsismttX509ProfessionInfo)

inline LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1IsismttX509ProfessionInfo_get_Rechtsanwltin(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1IsismttX509ProfessionInfo_Rechtsanwltin;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleAsn1IsismttX509ProfessionInfo, Rechtsanwltin, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)

inline LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1IsismttX509ProfessionInfo_get_Rechtsanwalt(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1IsismttX509ProfessionInfo_Rechtsanwalt;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleAsn1IsismttX509ProfessionInfo, Rechtsanwalt, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)

inline LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1IsismttX509ProfessionInfo_get_Rechtsbeistand(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1IsismttX509ProfessionInfo_Rechtsbeistand;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleAsn1IsismttX509ProfessionInfo, Rechtsbeistand, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)

inline LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1IsismttX509ProfessionInfo_get_Steuerberaterin(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1IsismttX509ProfessionInfo_Steuerberaterin;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleAsn1IsismttX509ProfessionInfo, Steuerberaterin, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)

inline LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1IsismttX509ProfessionInfo_get_Steuerberater(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1IsismttX509ProfessionInfo_Steuerberater;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleAsn1IsismttX509ProfessionInfo, Steuerberater, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)

inline LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1IsismttX509ProfessionInfo_get_Steuerbevollmchtigte(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1IsismttX509ProfessionInfo_Steuerbevollmchtigte;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleAsn1IsismttX509ProfessionInfo, Steuerbevollmchtigte, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)

inline LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1IsismttX509ProfessionInfo_get_Steuerbevollmchtigter(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1IsismttX509ProfessionInfo_Steuerbevollmchtigter;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleAsn1IsismttX509ProfessionInfo, Steuerbevollmchtigter, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)

inline LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1IsismttX509ProfessionInfo_get_Notarin(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1IsismttX509ProfessionInfo_Notarin;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleAsn1IsismttX509ProfessionInfo, Notarin, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)

inline LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1IsismttX509ProfessionInfo_get_Notar(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1IsismttX509ProfessionInfo_Notar;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleAsn1IsismttX509ProfessionInfo, Notar, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)

inline LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1IsismttX509ProfessionInfo_get_Notarvertreterin(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1IsismttX509ProfessionInfo_Notarvertreterin;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleAsn1IsismttX509ProfessionInfo, Notarvertreterin, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)

inline LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1IsismttX509ProfessionInfo_get_Notarvertreter(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1IsismttX509ProfessionInfo_Notarvertreter;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleAsn1IsismttX509ProfessionInfo, Notarvertreter, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)

inline LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1IsismttX509ProfessionInfo_get_Notariatsverwalterin(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1IsismttX509ProfessionInfo_Notariatsverwalterin;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleAsn1IsismttX509ProfessionInfo, Notariatsverwalterin, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)

inline LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1IsismttX509ProfessionInfo_get_Notariatsverwalter(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1IsismttX509ProfessionInfo_Notariatsverwalter;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleAsn1IsismttX509ProfessionInfo, Notariatsverwalter, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)

inline LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1IsismttX509ProfessionInfo_get_Wirtschaftsprferin(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1IsismttX509ProfessionInfo_Wirtschaftsprferin;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleAsn1IsismttX509ProfessionInfo, Wirtschaftsprferin, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)

inline LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1IsismttX509ProfessionInfo_get_Wirtschaftsprfer(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1IsismttX509ProfessionInfo_Wirtschaftsprfer;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleAsn1IsismttX509ProfessionInfo, Wirtschaftsprfer, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)

inline LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1IsismttX509ProfessionInfo_get_VereidigteBuchprferin(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1IsismttX509ProfessionInfo_VereidigteBuchprferin;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleAsn1IsismttX509ProfessionInfo, VereidigteBuchprferin, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)

inline LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1IsismttX509ProfessionInfo_get_VereidigterBuchprfer(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1IsismttX509ProfessionInfo_VereidigterBuchprfer;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleAsn1IsismttX509ProfessionInfo, VereidigterBuchprfer, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)

inline LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1IsismttX509ProfessionInfo_get_Patentanwltin(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1IsismttX509ProfessionInfo_Patentanwltin;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleAsn1IsismttX509ProfessionInfo, Patentanwltin, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)

inline LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1IsismttX509ProfessionInfo_get_Patentanwalt(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1IsismttX509ProfessionInfo_Patentanwalt;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleAsn1IsismttX509ProfessionInfo, Patentanwalt, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)

FOUNDATION_EXPORT LibOrgBouncycastleAsn1IsismttX509ProfessionInfo *LibOrgBouncycastleAsn1IsismttX509ProfessionInfo_getInstanceWithId_(id obj);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1IsismttX509ProfessionInfo_initWithLibOrgBouncycastleAsn1IsismttX509NamingAuthority_withLibOrgBouncycastleAsn1X500DirectoryStringArray_withLibOrgBouncycastleAsn1ASN1ObjectIdentifierArray_withNSString_withLibOrgBouncycastleAsn1ASN1OctetString_(LibOrgBouncycastleAsn1IsismttX509ProfessionInfo *self, LibOrgBouncycastleAsn1IsismttX509NamingAuthority *namingAuthority, IOSObjectArray *professionItems, IOSObjectArray *professionOIDs, NSString *registrationNumber, LibOrgBouncycastleAsn1ASN1OctetString *addProfessionInfo);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1IsismttX509ProfessionInfo *new_LibOrgBouncycastleAsn1IsismttX509ProfessionInfo_initWithLibOrgBouncycastleAsn1IsismttX509NamingAuthority_withLibOrgBouncycastleAsn1X500DirectoryStringArray_withLibOrgBouncycastleAsn1ASN1ObjectIdentifierArray_withNSString_withLibOrgBouncycastleAsn1ASN1OctetString_(LibOrgBouncycastleAsn1IsismttX509NamingAuthority *namingAuthority, IOSObjectArray *professionItems, IOSObjectArray *professionOIDs, NSString *registrationNumber, LibOrgBouncycastleAsn1ASN1OctetString *addProfessionInfo) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1IsismttX509ProfessionInfo *create_LibOrgBouncycastleAsn1IsismttX509ProfessionInfo_initWithLibOrgBouncycastleAsn1IsismttX509NamingAuthority_withLibOrgBouncycastleAsn1X500DirectoryStringArray_withLibOrgBouncycastleAsn1ASN1ObjectIdentifierArray_withNSString_withLibOrgBouncycastleAsn1ASN1OctetString_(LibOrgBouncycastleAsn1IsismttX509NamingAuthority *namingAuthority, IOSObjectArray *professionItems, IOSObjectArray *professionOIDs, NSString *registrationNumber, LibOrgBouncycastleAsn1ASN1OctetString *addProfessionInfo);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1IsismttX509ProfessionInfo)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // ProfessionInfo_H