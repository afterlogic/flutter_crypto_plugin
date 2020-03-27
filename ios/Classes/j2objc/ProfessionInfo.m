//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/isismtt/x509/ProfessionInfo.java
//

#include "ASN1Encodable.h"
#include "ASN1EncodableVector.h"
#include "ASN1Object.h"
#include "ASN1ObjectIdentifier.h"
#include "ASN1OctetString.h"
#include "ASN1Primitive.h"
#include "ASN1Sequence.h"
#include "ASN1TaggedObject.h"
#include "DEROctetString.h"
#include "DERPrintableString.h"
#include "DERSequence.h"
#include "DERTaggedObject.h"
#include "DirectoryString.h"
#include "IOSClass.h"
#include "IOSObjectArray.h"
#include "J2ObjC_source.h"
#include "NamingAuthority.h"
#include "ProfessionInfo.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/util/Enumeration.h"

@interface LibOrgBouncycastleAsn1IsismttX509ProfessionInfo () {
 @public
  LibOrgBouncycastleAsn1IsismttX509NamingAuthority *namingAuthority_;
  LibOrgBouncycastleAsn1ASN1Sequence *professionItems_;
  LibOrgBouncycastleAsn1ASN1Sequence *professionOIDs_;
  NSString *registrationNumber_;
  LibOrgBouncycastleAsn1ASN1OctetString *addProfessionInfo_;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1IsismttX509ProfessionInfo, namingAuthority_, LibOrgBouncycastleAsn1IsismttX509NamingAuthority *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1IsismttX509ProfessionInfo, professionItems_, LibOrgBouncycastleAsn1ASN1Sequence *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1IsismttX509ProfessionInfo, professionOIDs_, LibOrgBouncycastleAsn1ASN1Sequence *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1IsismttX509ProfessionInfo, registrationNumber_, NSString *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1IsismttX509ProfessionInfo, addProfessionInfo_, LibOrgBouncycastleAsn1ASN1OctetString *)

__attribute__((unused)) static void LibOrgBouncycastleAsn1IsismttX509ProfessionInfo_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1IsismttX509ProfessionInfo *self, LibOrgBouncycastleAsn1ASN1Sequence *seq);

__attribute__((unused)) static LibOrgBouncycastleAsn1IsismttX509ProfessionInfo *new_LibOrgBouncycastleAsn1IsismttX509ProfessionInfo_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleAsn1IsismttX509ProfessionInfo *create_LibOrgBouncycastleAsn1IsismttX509ProfessionInfo_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq);

J2OBJC_INITIALIZED_DEFN(LibOrgBouncycastleAsn1IsismttX509ProfessionInfo)

LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1IsismttX509ProfessionInfo_Rechtsanwltin;
LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1IsismttX509ProfessionInfo_Rechtsanwalt;
LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1IsismttX509ProfessionInfo_Rechtsbeistand;
LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1IsismttX509ProfessionInfo_Steuerberaterin;
LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1IsismttX509ProfessionInfo_Steuerberater;
LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1IsismttX509ProfessionInfo_Steuerbevollmchtigte;
LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1IsismttX509ProfessionInfo_Steuerbevollmchtigter;
LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1IsismttX509ProfessionInfo_Notarin;
LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1IsismttX509ProfessionInfo_Notar;
LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1IsismttX509ProfessionInfo_Notarvertreterin;
LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1IsismttX509ProfessionInfo_Notarvertreter;
LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1IsismttX509ProfessionInfo_Notariatsverwalterin;
LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1IsismttX509ProfessionInfo_Notariatsverwalter;
LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1IsismttX509ProfessionInfo_Wirtschaftsprferin;
LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1IsismttX509ProfessionInfo_Wirtschaftsprfer;
LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1IsismttX509ProfessionInfo_VereidigteBuchprferin;
LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1IsismttX509ProfessionInfo_VereidigterBuchprfer;
LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1IsismttX509ProfessionInfo_Patentanwltin;
LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1IsismttX509ProfessionInfo_Patentanwalt;

@implementation LibOrgBouncycastleAsn1IsismttX509ProfessionInfo

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)Rechtsanwltin {
  return LibOrgBouncycastleAsn1IsismttX509ProfessionInfo_Rechtsanwltin;
}

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)Rechtsanwalt {
  return LibOrgBouncycastleAsn1IsismttX509ProfessionInfo_Rechtsanwalt;
}

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)Rechtsbeistand {
  return LibOrgBouncycastleAsn1IsismttX509ProfessionInfo_Rechtsbeistand;
}

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)Steuerberaterin {
  return LibOrgBouncycastleAsn1IsismttX509ProfessionInfo_Steuerberaterin;
}

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)Steuerberater {
  return LibOrgBouncycastleAsn1IsismttX509ProfessionInfo_Steuerberater;
}

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)Steuerbevollmchtigte {
  return LibOrgBouncycastleAsn1IsismttX509ProfessionInfo_Steuerbevollmchtigte;
}

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)Steuerbevollmchtigter {
  return LibOrgBouncycastleAsn1IsismttX509ProfessionInfo_Steuerbevollmchtigter;
}

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)Notarin {
  return LibOrgBouncycastleAsn1IsismttX509ProfessionInfo_Notarin;
}

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)Notar {
  return LibOrgBouncycastleAsn1IsismttX509ProfessionInfo_Notar;
}

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)Notarvertreterin {
  return LibOrgBouncycastleAsn1IsismttX509ProfessionInfo_Notarvertreterin;
}

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)Notarvertreter {
  return LibOrgBouncycastleAsn1IsismttX509ProfessionInfo_Notarvertreter;
}

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)Notariatsverwalterin {
  return LibOrgBouncycastleAsn1IsismttX509ProfessionInfo_Notariatsverwalterin;
}

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)Notariatsverwalter {
  return LibOrgBouncycastleAsn1IsismttX509ProfessionInfo_Notariatsverwalter;
}

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)Wirtschaftsprferin {
  return LibOrgBouncycastleAsn1IsismttX509ProfessionInfo_Wirtschaftsprferin;
}

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)Wirtschaftsprfer {
  return LibOrgBouncycastleAsn1IsismttX509ProfessionInfo_Wirtschaftsprfer;
}

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)VereidigteBuchprferin {
  return LibOrgBouncycastleAsn1IsismttX509ProfessionInfo_VereidigteBuchprferin;
}

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)VereidigterBuchprfer {
  return LibOrgBouncycastleAsn1IsismttX509ProfessionInfo_VereidigterBuchprfer;
}

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)Patentanwltin {
  return LibOrgBouncycastleAsn1IsismttX509ProfessionInfo_Patentanwltin;
}

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)Patentanwalt {
  return LibOrgBouncycastleAsn1IsismttX509ProfessionInfo_Patentanwalt;
}

+ (LibOrgBouncycastleAsn1IsismttX509ProfessionInfo *)getInstanceWithId:(id)obj {
  return LibOrgBouncycastleAsn1IsismttX509ProfessionInfo_getInstanceWithId_(obj);
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq {
  LibOrgBouncycastleAsn1IsismttX509ProfessionInfo_initWithLibOrgBouncycastleAsn1ASN1Sequence_(self, seq);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleAsn1IsismttX509NamingAuthority:(LibOrgBouncycastleAsn1IsismttX509NamingAuthority *)namingAuthority
                      withLibOrgBouncycastleAsn1X500DirectoryStringArray:(IOSObjectArray *)professionItems
                     withLibOrgBouncycastleAsn1ASN1ObjectIdentifierArray:(IOSObjectArray *)professionOIDs
                                                            withNSString:(NSString *)registrationNumber
                               withLibOrgBouncycastleAsn1ASN1OctetString:(LibOrgBouncycastleAsn1ASN1OctetString *)addProfessionInfo {
  LibOrgBouncycastleAsn1IsismttX509ProfessionInfo_initWithLibOrgBouncycastleAsn1IsismttX509NamingAuthority_withLibOrgBouncycastleAsn1X500DirectoryStringArray_withLibOrgBouncycastleAsn1ASN1ObjectIdentifierArray_withNSString_withLibOrgBouncycastleAsn1ASN1OctetString_(self, namingAuthority, professionItems, professionOIDs, registrationNumber, addProfessionInfo);
  return self;
}

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive {
  LibOrgBouncycastleAsn1ASN1EncodableVector *vec = new_LibOrgBouncycastleAsn1ASN1EncodableVector_init();
  if (namingAuthority_ != nil) {
    [vec addWithLibOrgBouncycastleAsn1ASN1Encodable:new_LibOrgBouncycastleAsn1DERTaggedObject_initWithBoolean_withInt_withLibOrgBouncycastleAsn1ASN1Encodable_(true, 0, namingAuthority_)];
  }
  [vec addWithLibOrgBouncycastleAsn1ASN1Encodable:professionItems_];
  if (professionOIDs_ != nil) {
    [vec addWithLibOrgBouncycastleAsn1ASN1Encodable:professionOIDs_];
  }
  if (registrationNumber_ != nil) {
    [vec addWithLibOrgBouncycastleAsn1ASN1Encodable:new_LibOrgBouncycastleAsn1DERPrintableString_initWithNSString_withBoolean_(registrationNumber_, true)];
  }
  if (addProfessionInfo_ != nil) {
    [vec addWithLibOrgBouncycastleAsn1ASN1Encodable:addProfessionInfo_];
  }
  return new_LibOrgBouncycastleAsn1DERSequence_initWithLibOrgBouncycastleAsn1ASN1EncodableVector_(vec);
}

- (LibOrgBouncycastleAsn1ASN1OctetString *)getAddProfessionInfo {
  return addProfessionInfo_;
}

- (LibOrgBouncycastleAsn1IsismttX509NamingAuthority *)getNamingAuthority {
  return namingAuthority_;
}

- (IOSObjectArray *)getProfessionItems {
  IOSObjectArray *items = [IOSObjectArray newArrayWithLength:[((LibOrgBouncycastleAsn1ASN1Sequence *) nil_chk(professionItems_)) size] type:LibOrgBouncycastleAsn1X500DirectoryString_class_()];
  jint count = 0;
  for (id<JavaUtilEnumeration> e = [((LibOrgBouncycastleAsn1ASN1Sequence *) nil_chk(professionItems_)) getObjects]; [((id<JavaUtilEnumeration>) nil_chk(e)) hasMoreElements]; ) {
    (void) IOSObjectArray_Set(items, count++, LibOrgBouncycastleAsn1X500DirectoryString_getInstanceWithId_([e nextElement]));
  }
  return items;
}

- (IOSObjectArray *)getProfessionOIDs {
  if (professionOIDs_ == nil) {
    return [IOSObjectArray newArrayWithLength:0 type:LibOrgBouncycastleAsn1ASN1ObjectIdentifier_class_()];
  }
  IOSObjectArray *oids = [IOSObjectArray newArrayWithLength:[professionOIDs_ size] type:LibOrgBouncycastleAsn1ASN1ObjectIdentifier_class_()];
  jint count = 0;
  for (id<JavaUtilEnumeration> e = [((LibOrgBouncycastleAsn1ASN1Sequence *) nil_chk(professionOIDs_)) getObjects]; [((id<JavaUtilEnumeration>) nil_chk(e)) hasMoreElements]; ) {
    (void) IOSObjectArray_Set(oids, count++, LibOrgBouncycastleAsn1ASN1ObjectIdentifier_getInstanceWithId_([e nextElement]));
  }
  return oids;
}

- (NSString *)getRegistrationNumber {
  return registrationNumber_;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, "LLibOrgBouncycastleAsn1IsismttX509ProfessionInfo;", 0x9, 0, 1, -1, -1, -1, -1 },
    { NULL, NULL, 0x2, -1, 2, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 3, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1OctetString;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1IsismttX509NamingAuthority;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[LLibOrgBouncycastleAsn1X500DirectoryString;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(getInstanceWithId:);
  methods[1].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1Sequence:);
  methods[2].selector = @selector(initWithLibOrgBouncycastleAsn1IsismttX509NamingAuthority:withLibOrgBouncycastleAsn1X500DirectoryStringArray:withLibOrgBouncycastleAsn1ASN1ObjectIdentifierArray:withNSString:withLibOrgBouncycastleAsn1ASN1OctetString:);
  methods[3].selector = @selector(toASN1Primitive);
  methods[4].selector = @selector(getAddProfessionInfo);
  methods[5].selector = @selector(getNamingAuthority);
  methods[6].selector = @selector(getProfessionItems);
  methods[7].selector = @selector(getProfessionOIDs);
  methods[8].selector = @selector(getRegistrationNumber);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "Rechtsanwltin", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 4, -1, -1 },
    { "Rechtsanwalt", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 5, -1, -1 },
    { "Rechtsbeistand", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 6, -1, -1 },
    { "Steuerberaterin", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 7, -1, -1 },
    { "Steuerberater", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 8, -1, -1 },
    { "Steuerbevollmchtigte", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 9, -1, -1 },
    { "Steuerbevollmchtigter", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 10, -1, -1 },
    { "Notarin", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 11, -1, -1 },
    { "Notar", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 12, -1, -1 },
    { "Notarvertreterin", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 13, -1, -1 },
    { "Notarvertreter", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 14, -1, -1 },
    { "Notariatsverwalterin", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 15, -1, -1 },
    { "Notariatsverwalter", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 16, -1, -1 },
    { "Wirtschaftsprferin", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 17, -1, -1 },
    { "Wirtschaftsprfer", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 18, -1, -1 },
    { "VereidigteBuchprferin", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 19, -1, -1 },
    { "VereidigterBuchprfer", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 20, -1, -1 },
    { "Patentanwltin", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 21, -1, -1 },
    { "Patentanwalt", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 22, -1, -1 },
    { "namingAuthority_", "LLibOrgBouncycastleAsn1IsismttX509NamingAuthority;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "professionItems_", "LLibOrgBouncycastleAsn1ASN1Sequence;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "professionOIDs_", "LLibOrgBouncycastleAsn1ASN1Sequence;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "registrationNumber_", "LNSString;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "addProfessionInfo_", "LLibOrgBouncycastleAsn1ASN1OctetString;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "getInstance", "LNSObject;", "LLibOrgBouncycastleAsn1ASN1Sequence;", "LLibOrgBouncycastleAsn1IsismttX509NamingAuthority;[LLibOrgBouncycastleAsn1X500DirectoryString;[LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;LNSString;LLibOrgBouncycastleAsn1ASN1OctetString;", &LibOrgBouncycastleAsn1IsismttX509ProfessionInfo_Rechtsanwltin, &LibOrgBouncycastleAsn1IsismttX509ProfessionInfo_Rechtsanwalt, &LibOrgBouncycastleAsn1IsismttX509ProfessionInfo_Rechtsbeistand, &LibOrgBouncycastleAsn1IsismttX509ProfessionInfo_Steuerberaterin, &LibOrgBouncycastleAsn1IsismttX509ProfessionInfo_Steuerberater, &LibOrgBouncycastleAsn1IsismttX509ProfessionInfo_Steuerbevollmchtigte, &LibOrgBouncycastleAsn1IsismttX509ProfessionInfo_Steuerbevollmchtigter, &LibOrgBouncycastleAsn1IsismttX509ProfessionInfo_Notarin, &LibOrgBouncycastleAsn1IsismttX509ProfessionInfo_Notar, &LibOrgBouncycastleAsn1IsismttX509ProfessionInfo_Notarvertreterin, &LibOrgBouncycastleAsn1IsismttX509ProfessionInfo_Notarvertreter, &LibOrgBouncycastleAsn1IsismttX509ProfessionInfo_Notariatsverwalterin, &LibOrgBouncycastleAsn1IsismttX509ProfessionInfo_Notariatsverwalter, &LibOrgBouncycastleAsn1IsismttX509ProfessionInfo_Wirtschaftsprferin, &LibOrgBouncycastleAsn1IsismttX509ProfessionInfo_Wirtschaftsprfer, &LibOrgBouncycastleAsn1IsismttX509ProfessionInfo_VereidigteBuchprferin, &LibOrgBouncycastleAsn1IsismttX509ProfessionInfo_VereidigterBuchprfer, &LibOrgBouncycastleAsn1IsismttX509ProfessionInfo_Patentanwltin, &LibOrgBouncycastleAsn1IsismttX509ProfessionInfo_Patentanwalt };
  static const J2ObjcClassInfo _LibOrgBouncycastleAsn1IsismttX509ProfessionInfo = { "ProfessionInfo", "lib.org.bouncycastle.asn1.isismtt.x509", ptrTable, methods, fields, 7, 0x1, 9, 24, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleAsn1IsismttX509ProfessionInfo;
}

+ (void)initialize {
  if (self == [LibOrgBouncycastleAsn1IsismttX509ProfessionInfo class]) {
    LibOrgBouncycastleAsn1IsismttX509ProfessionInfo_Rechtsanwltin = new_LibOrgBouncycastleAsn1ASN1ObjectIdentifier_initWithNSString_(JreStrcat("@$", JreLoadStatic(LibOrgBouncycastleAsn1IsismttX509NamingAuthority, id_isismtt_at_namingAuthorities_RechtWirtschaftSteuern), @".1"));
    LibOrgBouncycastleAsn1IsismttX509ProfessionInfo_Rechtsanwalt = new_LibOrgBouncycastleAsn1ASN1ObjectIdentifier_initWithNSString_(JreStrcat("@$", JreLoadStatic(LibOrgBouncycastleAsn1IsismttX509NamingAuthority, id_isismtt_at_namingAuthorities_RechtWirtschaftSteuern), @".2"));
    LibOrgBouncycastleAsn1IsismttX509ProfessionInfo_Rechtsbeistand = new_LibOrgBouncycastleAsn1ASN1ObjectIdentifier_initWithNSString_(JreStrcat("@$", JreLoadStatic(LibOrgBouncycastleAsn1IsismttX509NamingAuthority, id_isismtt_at_namingAuthorities_RechtWirtschaftSteuern), @".3"));
    LibOrgBouncycastleAsn1IsismttX509ProfessionInfo_Steuerberaterin = new_LibOrgBouncycastleAsn1ASN1ObjectIdentifier_initWithNSString_(JreStrcat("@$", JreLoadStatic(LibOrgBouncycastleAsn1IsismttX509NamingAuthority, id_isismtt_at_namingAuthorities_RechtWirtschaftSteuern), @".4"));
    LibOrgBouncycastleAsn1IsismttX509ProfessionInfo_Steuerberater = new_LibOrgBouncycastleAsn1ASN1ObjectIdentifier_initWithNSString_(JreStrcat("@$", JreLoadStatic(LibOrgBouncycastleAsn1IsismttX509NamingAuthority, id_isismtt_at_namingAuthorities_RechtWirtschaftSteuern), @".5"));
    LibOrgBouncycastleAsn1IsismttX509ProfessionInfo_Steuerbevollmchtigte = new_LibOrgBouncycastleAsn1ASN1ObjectIdentifier_initWithNSString_(JreStrcat("@$", JreLoadStatic(LibOrgBouncycastleAsn1IsismttX509NamingAuthority, id_isismtt_at_namingAuthorities_RechtWirtschaftSteuern), @".6"));
    LibOrgBouncycastleAsn1IsismttX509ProfessionInfo_Steuerbevollmchtigter = new_LibOrgBouncycastleAsn1ASN1ObjectIdentifier_initWithNSString_(JreStrcat("@$", JreLoadStatic(LibOrgBouncycastleAsn1IsismttX509NamingAuthority, id_isismtt_at_namingAuthorities_RechtWirtschaftSteuern), @".7"));
    LibOrgBouncycastleAsn1IsismttX509ProfessionInfo_Notarin = new_LibOrgBouncycastleAsn1ASN1ObjectIdentifier_initWithNSString_(JreStrcat("@$", JreLoadStatic(LibOrgBouncycastleAsn1IsismttX509NamingAuthority, id_isismtt_at_namingAuthorities_RechtWirtschaftSteuern), @".8"));
    LibOrgBouncycastleAsn1IsismttX509ProfessionInfo_Notar = new_LibOrgBouncycastleAsn1ASN1ObjectIdentifier_initWithNSString_(JreStrcat("@$", JreLoadStatic(LibOrgBouncycastleAsn1IsismttX509NamingAuthority, id_isismtt_at_namingAuthorities_RechtWirtschaftSteuern), @".9"));
    LibOrgBouncycastleAsn1IsismttX509ProfessionInfo_Notarvertreterin = new_LibOrgBouncycastleAsn1ASN1ObjectIdentifier_initWithNSString_(JreStrcat("@$", JreLoadStatic(LibOrgBouncycastleAsn1IsismttX509NamingAuthority, id_isismtt_at_namingAuthorities_RechtWirtschaftSteuern), @".10"));
    LibOrgBouncycastleAsn1IsismttX509ProfessionInfo_Notarvertreter = new_LibOrgBouncycastleAsn1ASN1ObjectIdentifier_initWithNSString_(JreStrcat("@$", JreLoadStatic(LibOrgBouncycastleAsn1IsismttX509NamingAuthority, id_isismtt_at_namingAuthorities_RechtWirtschaftSteuern), @".11"));
    LibOrgBouncycastleAsn1IsismttX509ProfessionInfo_Notariatsverwalterin = new_LibOrgBouncycastleAsn1ASN1ObjectIdentifier_initWithNSString_(JreStrcat("@$", JreLoadStatic(LibOrgBouncycastleAsn1IsismttX509NamingAuthority, id_isismtt_at_namingAuthorities_RechtWirtschaftSteuern), @".12"));
    LibOrgBouncycastleAsn1IsismttX509ProfessionInfo_Notariatsverwalter = new_LibOrgBouncycastleAsn1ASN1ObjectIdentifier_initWithNSString_(JreStrcat("@$", JreLoadStatic(LibOrgBouncycastleAsn1IsismttX509NamingAuthority, id_isismtt_at_namingAuthorities_RechtWirtschaftSteuern), @".13"));
    LibOrgBouncycastleAsn1IsismttX509ProfessionInfo_Wirtschaftsprferin = new_LibOrgBouncycastleAsn1ASN1ObjectIdentifier_initWithNSString_(JreStrcat("@$", JreLoadStatic(LibOrgBouncycastleAsn1IsismttX509NamingAuthority, id_isismtt_at_namingAuthorities_RechtWirtschaftSteuern), @".14"));
    LibOrgBouncycastleAsn1IsismttX509ProfessionInfo_Wirtschaftsprfer = new_LibOrgBouncycastleAsn1ASN1ObjectIdentifier_initWithNSString_(JreStrcat("@$", JreLoadStatic(LibOrgBouncycastleAsn1IsismttX509NamingAuthority, id_isismtt_at_namingAuthorities_RechtWirtschaftSteuern), @".15"));
    LibOrgBouncycastleAsn1IsismttX509ProfessionInfo_VereidigteBuchprferin = new_LibOrgBouncycastleAsn1ASN1ObjectIdentifier_initWithNSString_(JreStrcat("@$", JreLoadStatic(LibOrgBouncycastleAsn1IsismttX509NamingAuthority, id_isismtt_at_namingAuthorities_RechtWirtschaftSteuern), @".16"));
    LibOrgBouncycastleAsn1IsismttX509ProfessionInfo_VereidigterBuchprfer = new_LibOrgBouncycastleAsn1ASN1ObjectIdentifier_initWithNSString_(JreStrcat("@$", JreLoadStatic(LibOrgBouncycastleAsn1IsismttX509NamingAuthority, id_isismtt_at_namingAuthorities_RechtWirtschaftSteuern), @".17"));
    LibOrgBouncycastleAsn1IsismttX509ProfessionInfo_Patentanwltin = new_LibOrgBouncycastleAsn1ASN1ObjectIdentifier_initWithNSString_(JreStrcat("@$", JreLoadStatic(LibOrgBouncycastleAsn1IsismttX509NamingAuthority, id_isismtt_at_namingAuthorities_RechtWirtschaftSteuern), @".18"));
    LibOrgBouncycastleAsn1IsismttX509ProfessionInfo_Patentanwalt = new_LibOrgBouncycastleAsn1ASN1ObjectIdentifier_initWithNSString_(JreStrcat("@$", JreLoadStatic(LibOrgBouncycastleAsn1IsismttX509NamingAuthority, id_isismtt_at_namingAuthorities_RechtWirtschaftSteuern), @".19"));
    J2OBJC_SET_INITIALIZED(LibOrgBouncycastleAsn1IsismttX509ProfessionInfo)
  }
}

@end

LibOrgBouncycastleAsn1IsismttX509ProfessionInfo *LibOrgBouncycastleAsn1IsismttX509ProfessionInfo_getInstanceWithId_(id obj) {
  LibOrgBouncycastleAsn1IsismttX509ProfessionInfo_initialize();
  if (obj == nil || [obj isKindOfClass:[LibOrgBouncycastleAsn1IsismttX509ProfessionInfo class]]) {
    return (LibOrgBouncycastleAsn1IsismttX509ProfessionInfo *) cast_chk(obj, [LibOrgBouncycastleAsn1IsismttX509ProfessionInfo class]);
  }
  if ([obj isKindOfClass:[LibOrgBouncycastleAsn1ASN1Sequence class]]) {
    return new_LibOrgBouncycastleAsn1IsismttX509ProfessionInfo_initWithLibOrgBouncycastleAsn1ASN1Sequence_((LibOrgBouncycastleAsn1ASN1Sequence *) obj);
  }
  @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$$", @"illegal object in getInstance: ", [[obj java_getClass] getName]));
}

void LibOrgBouncycastleAsn1IsismttX509ProfessionInfo_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1IsismttX509ProfessionInfo *self, LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  if ([((LibOrgBouncycastleAsn1ASN1Sequence *) nil_chk(seq)) size] > 5) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$I", @"Bad sequence size: ", [seq size]));
  }
  id<JavaUtilEnumeration> e = [seq getObjects];
  id<LibOrgBouncycastleAsn1ASN1Encodable> o = (id<LibOrgBouncycastleAsn1ASN1Encodable>) cast_check([((id<JavaUtilEnumeration>) nil_chk(e)) nextElement], LibOrgBouncycastleAsn1ASN1Encodable_class_());
  if ([o isKindOfClass:[LibOrgBouncycastleAsn1ASN1TaggedObject class]]) {
    if ([((LibOrgBouncycastleAsn1ASN1TaggedObject *) nil_chk(((LibOrgBouncycastleAsn1ASN1TaggedObject *) o))) getTagNo] != 0) {
      @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$I", @"Bad tag number: ", [((LibOrgBouncycastleAsn1ASN1TaggedObject *) nil_chk(((LibOrgBouncycastleAsn1ASN1TaggedObject *) o))) getTagNo]));
    }
    self->namingAuthority_ = LibOrgBouncycastleAsn1IsismttX509NamingAuthority_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_((LibOrgBouncycastleAsn1ASN1TaggedObject *) o, true);
    o = (id<LibOrgBouncycastleAsn1ASN1Encodable>) cast_check([e nextElement], LibOrgBouncycastleAsn1ASN1Encodable_class_());
  }
  self->professionItems_ = LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithId_(o);
  if ([e hasMoreElements]) {
    o = (id<LibOrgBouncycastleAsn1ASN1Encodable>) cast_check([e nextElement], LibOrgBouncycastleAsn1ASN1Encodable_class_());
    if ([o isKindOfClass:[LibOrgBouncycastleAsn1ASN1Sequence class]]) {
      self->professionOIDs_ = LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithId_(o);
    }
    else if ([o isKindOfClass:[LibOrgBouncycastleAsn1DERPrintableString class]]) {
      self->registrationNumber_ = [((LibOrgBouncycastleAsn1DERPrintableString *) nil_chk(LibOrgBouncycastleAsn1DERPrintableString_getInstanceWithId_(o))) getString];
    }
    else if ([o isKindOfClass:[LibOrgBouncycastleAsn1ASN1OctetString class]]) {
      self->addProfessionInfo_ = LibOrgBouncycastleAsn1ASN1OctetString_getInstanceWithId_(o);
    }
    else {
      @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$@", @"Bad object encountered: ", [((id<LibOrgBouncycastleAsn1ASN1Encodable>) nil_chk(o)) java_getClass]));
    }
  }
  if ([e hasMoreElements]) {
    o = (id<LibOrgBouncycastleAsn1ASN1Encodable>) cast_check([e nextElement], LibOrgBouncycastleAsn1ASN1Encodable_class_());
    if ([o isKindOfClass:[LibOrgBouncycastleAsn1DERPrintableString class]]) {
      self->registrationNumber_ = [((LibOrgBouncycastleAsn1DERPrintableString *) nil_chk(LibOrgBouncycastleAsn1DERPrintableString_getInstanceWithId_(o))) getString];
    }
    else if ([o isKindOfClass:[LibOrgBouncycastleAsn1DEROctetString class]]) {
      self->addProfessionInfo_ = (LibOrgBouncycastleAsn1DEROctetString *) o;
    }
    else {
      @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$@", @"Bad object encountered: ", [((id<LibOrgBouncycastleAsn1ASN1Encodable>) nil_chk(o)) java_getClass]));
    }
  }
  if ([e hasMoreElements]) {
    o = (id<LibOrgBouncycastleAsn1ASN1Encodable>) cast_check([e nextElement], LibOrgBouncycastleAsn1ASN1Encodable_class_());
    if ([o isKindOfClass:[LibOrgBouncycastleAsn1DEROctetString class]]) {
      self->addProfessionInfo_ = (LibOrgBouncycastleAsn1DEROctetString *) o;
    }
    else {
      @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$@", @"Bad object encountered: ", [((id<LibOrgBouncycastleAsn1ASN1Encodable>) nil_chk(o)) java_getClass]));
    }
  }
}

LibOrgBouncycastleAsn1IsismttX509ProfessionInfo *new_LibOrgBouncycastleAsn1IsismttX509ProfessionInfo_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1IsismttX509ProfessionInfo, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

LibOrgBouncycastleAsn1IsismttX509ProfessionInfo *create_LibOrgBouncycastleAsn1IsismttX509ProfessionInfo_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1IsismttX509ProfessionInfo, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

void LibOrgBouncycastleAsn1IsismttX509ProfessionInfo_initWithLibOrgBouncycastleAsn1IsismttX509NamingAuthority_withLibOrgBouncycastleAsn1X500DirectoryStringArray_withLibOrgBouncycastleAsn1ASN1ObjectIdentifierArray_withNSString_withLibOrgBouncycastleAsn1ASN1OctetString_(LibOrgBouncycastleAsn1IsismttX509ProfessionInfo *self, LibOrgBouncycastleAsn1IsismttX509NamingAuthority *namingAuthority, IOSObjectArray *professionItems, IOSObjectArray *professionOIDs, NSString *registrationNumber, LibOrgBouncycastleAsn1ASN1OctetString *addProfessionInfo) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->namingAuthority_ = namingAuthority;
  LibOrgBouncycastleAsn1ASN1EncodableVector *v = new_LibOrgBouncycastleAsn1ASN1EncodableVector_init();
  for (jint i = 0; i != ((IOSObjectArray *) nil_chk(professionItems))->size_; i++) {
    [v addWithLibOrgBouncycastleAsn1ASN1Encodable:IOSObjectArray_Get(professionItems, i)];
  }
  self->professionItems_ = new_LibOrgBouncycastleAsn1DERSequence_initWithLibOrgBouncycastleAsn1ASN1EncodableVector_(v);
  if (professionOIDs != nil) {
    v = new_LibOrgBouncycastleAsn1ASN1EncodableVector_init();
    for (jint i = 0; i != professionOIDs->size_; i++) {
      [v addWithLibOrgBouncycastleAsn1ASN1Encodable:IOSObjectArray_Get(professionOIDs, i)];
    }
    self->professionOIDs_ = new_LibOrgBouncycastleAsn1DERSequence_initWithLibOrgBouncycastleAsn1ASN1EncodableVector_(v);
  }
  self->registrationNumber_ = registrationNumber;
  self->addProfessionInfo_ = addProfessionInfo;
}

LibOrgBouncycastleAsn1IsismttX509ProfessionInfo *new_LibOrgBouncycastleAsn1IsismttX509ProfessionInfo_initWithLibOrgBouncycastleAsn1IsismttX509NamingAuthority_withLibOrgBouncycastleAsn1X500DirectoryStringArray_withLibOrgBouncycastleAsn1ASN1ObjectIdentifierArray_withNSString_withLibOrgBouncycastleAsn1ASN1OctetString_(LibOrgBouncycastleAsn1IsismttX509NamingAuthority *namingAuthority, IOSObjectArray *professionItems, IOSObjectArray *professionOIDs, NSString *registrationNumber, LibOrgBouncycastleAsn1ASN1OctetString *addProfessionInfo) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1IsismttX509ProfessionInfo, initWithLibOrgBouncycastleAsn1IsismttX509NamingAuthority_withLibOrgBouncycastleAsn1X500DirectoryStringArray_withLibOrgBouncycastleAsn1ASN1ObjectIdentifierArray_withNSString_withLibOrgBouncycastleAsn1ASN1OctetString_, namingAuthority, professionItems, professionOIDs, registrationNumber, addProfessionInfo)
}

LibOrgBouncycastleAsn1IsismttX509ProfessionInfo *create_LibOrgBouncycastleAsn1IsismttX509ProfessionInfo_initWithLibOrgBouncycastleAsn1IsismttX509NamingAuthority_withLibOrgBouncycastleAsn1X500DirectoryStringArray_withLibOrgBouncycastleAsn1ASN1ObjectIdentifierArray_withNSString_withLibOrgBouncycastleAsn1ASN1OctetString_(LibOrgBouncycastleAsn1IsismttX509NamingAuthority *namingAuthority, IOSObjectArray *professionItems, IOSObjectArray *professionOIDs, NSString *registrationNumber, LibOrgBouncycastleAsn1ASN1OctetString *addProfessionInfo) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1IsismttX509ProfessionInfo, initWithLibOrgBouncycastleAsn1IsismttX509NamingAuthority_withLibOrgBouncycastleAsn1X500DirectoryStringArray_withLibOrgBouncycastleAsn1ASN1ObjectIdentifierArray_withNSString_withLibOrgBouncycastleAsn1ASN1OctetString_, namingAuthority, professionItems, professionOIDs, registrationNumber, addProfessionInfo)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleAsn1IsismttX509ProfessionInfo)
