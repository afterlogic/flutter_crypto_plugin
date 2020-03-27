//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/cmp/PKIHeader.java
//

#include "ASN1Encodable.h"
#include "ASN1EncodableVector.h"
#include "ASN1GeneralizedTime.h"
#include "ASN1Integer.h"
#include "ASN1Object.h"
#include "ASN1OctetString.h"
#include "ASN1Primitive.h"
#include "ASN1Sequence.h"
#include "ASN1TaggedObject.h"
#include "AlgorithmIdentifier.h"
#include "DERSequence.h"
#include "DERTaggedObject.h"
#include "GeneralName.h"
#include "IOSClass.h"
#include "IOSObjectArray.h"
#include "InfoTypeAndValue.h"
#include "J2ObjC_source.h"
#include "PKIFreeText.h"
#include "PKIHeader.h"
#include "X500Name.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/util/Enumeration.h"

@interface LibOrgBouncycastleAsn1CmpPKIHeader () {
 @public
  LibOrgBouncycastleAsn1ASN1Integer *pvno_;
  LibOrgBouncycastleAsn1X509GeneralName *sender_;
  LibOrgBouncycastleAsn1X509GeneralName *recipient_;
  LibOrgBouncycastleAsn1ASN1GeneralizedTime *messageTime_;
  LibOrgBouncycastleAsn1X509AlgorithmIdentifier *protectionAlg_;
  LibOrgBouncycastleAsn1ASN1OctetString *senderKID_;
  LibOrgBouncycastleAsn1ASN1OctetString *recipKID_;
  LibOrgBouncycastleAsn1ASN1OctetString *transactionID_;
  LibOrgBouncycastleAsn1ASN1OctetString *senderNonce_;
  LibOrgBouncycastleAsn1ASN1OctetString *recipNonce_;
  LibOrgBouncycastleAsn1CmpPKIFreeText *freeText_;
  LibOrgBouncycastleAsn1ASN1Sequence *generalInfo_;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq;

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Integer:(LibOrgBouncycastleAsn1ASN1Integer *)pvno
                withLibOrgBouncycastleAsn1X509GeneralName:(LibOrgBouncycastleAsn1X509GeneralName *)sender
                withLibOrgBouncycastleAsn1X509GeneralName:(LibOrgBouncycastleAsn1X509GeneralName *)recipient;

- (void)addOptionalWithLibOrgBouncycastleAsn1ASN1EncodableVector:(LibOrgBouncycastleAsn1ASN1EncodableVector *)v
                                                         withInt:(jint)tagNo
                         withLibOrgBouncycastleAsn1ASN1Encodable:(id<LibOrgBouncycastleAsn1ASN1Encodable>)obj;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1CmpPKIHeader, pvno_, LibOrgBouncycastleAsn1ASN1Integer *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1CmpPKIHeader, sender_, LibOrgBouncycastleAsn1X509GeneralName *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1CmpPKIHeader, recipient_, LibOrgBouncycastleAsn1X509GeneralName *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1CmpPKIHeader, messageTime_, LibOrgBouncycastleAsn1ASN1GeneralizedTime *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1CmpPKIHeader, protectionAlg_, LibOrgBouncycastleAsn1X509AlgorithmIdentifier *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1CmpPKIHeader, senderKID_, LibOrgBouncycastleAsn1ASN1OctetString *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1CmpPKIHeader, recipKID_, LibOrgBouncycastleAsn1ASN1OctetString *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1CmpPKIHeader, transactionID_, LibOrgBouncycastleAsn1ASN1OctetString *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1CmpPKIHeader, senderNonce_, LibOrgBouncycastleAsn1ASN1OctetString *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1CmpPKIHeader, recipNonce_, LibOrgBouncycastleAsn1ASN1OctetString *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1CmpPKIHeader, freeText_, LibOrgBouncycastleAsn1CmpPKIFreeText *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1CmpPKIHeader, generalInfo_, LibOrgBouncycastleAsn1ASN1Sequence *)

__attribute__((unused)) static void LibOrgBouncycastleAsn1CmpPKIHeader_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1CmpPKIHeader *self, LibOrgBouncycastleAsn1ASN1Sequence *seq);

__attribute__((unused)) static LibOrgBouncycastleAsn1CmpPKIHeader *new_LibOrgBouncycastleAsn1CmpPKIHeader_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleAsn1CmpPKIHeader *create_LibOrgBouncycastleAsn1CmpPKIHeader_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq);

__attribute__((unused)) static void LibOrgBouncycastleAsn1CmpPKIHeader_initWithLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1X509GeneralName_withLibOrgBouncycastleAsn1X509GeneralName_(LibOrgBouncycastleAsn1CmpPKIHeader *self, LibOrgBouncycastleAsn1ASN1Integer *pvno, LibOrgBouncycastleAsn1X509GeneralName *sender, LibOrgBouncycastleAsn1X509GeneralName *recipient);

__attribute__((unused)) static LibOrgBouncycastleAsn1CmpPKIHeader *new_LibOrgBouncycastleAsn1CmpPKIHeader_initWithLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1X509GeneralName_withLibOrgBouncycastleAsn1X509GeneralName_(LibOrgBouncycastleAsn1ASN1Integer *pvno, LibOrgBouncycastleAsn1X509GeneralName *sender, LibOrgBouncycastleAsn1X509GeneralName *recipient) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleAsn1CmpPKIHeader *create_LibOrgBouncycastleAsn1CmpPKIHeader_initWithLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1X509GeneralName_withLibOrgBouncycastleAsn1X509GeneralName_(LibOrgBouncycastleAsn1ASN1Integer *pvno, LibOrgBouncycastleAsn1X509GeneralName *sender, LibOrgBouncycastleAsn1X509GeneralName *recipient);

__attribute__((unused)) static void LibOrgBouncycastleAsn1CmpPKIHeader_addOptionalWithLibOrgBouncycastleAsn1ASN1EncodableVector_withInt_withLibOrgBouncycastleAsn1ASN1Encodable_(LibOrgBouncycastleAsn1CmpPKIHeader *self, LibOrgBouncycastleAsn1ASN1EncodableVector *v, jint tagNo, id<LibOrgBouncycastleAsn1ASN1Encodable> obj);

J2OBJC_INITIALIZED_DEFN(LibOrgBouncycastleAsn1CmpPKIHeader)

LibOrgBouncycastleAsn1X509GeneralName *LibOrgBouncycastleAsn1CmpPKIHeader_NULL_NAME;

@implementation LibOrgBouncycastleAsn1CmpPKIHeader

+ (LibOrgBouncycastleAsn1X509GeneralName *)NULL_NAME {
  return LibOrgBouncycastleAsn1CmpPKIHeader_NULL_NAME;
}

+ (jint)CMP_1999 {
  return LibOrgBouncycastleAsn1CmpPKIHeader_CMP_1999;
}

+ (jint)CMP_2000 {
  return LibOrgBouncycastleAsn1CmpPKIHeader_CMP_2000;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq {
  LibOrgBouncycastleAsn1CmpPKIHeader_initWithLibOrgBouncycastleAsn1ASN1Sequence_(self, seq);
  return self;
}

+ (LibOrgBouncycastleAsn1CmpPKIHeader *)getInstanceWithId:(id)o {
  return LibOrgBouncycastleAsn1CmpPKIHeader_getInstanceWithId_(o);
}

- (instancetype)initWithInt:(jint)pvno
withLibOrgBouncycastleAsn1X509GeneralName:(LibOrgBouncycastleAsn1X509GeneralName *)sender
withLibOrgBouncycastleAsn1X509GeneralName:(LibOrgBouncycastleAsn1X509GeneralName *)recipient {
  LibOrgBouncycastleAsn1CmpPKIHeader_initWithInt_withLibOrgBouncycastleAsn1X509GeneralName_withLibOrgBouncycastleAsn1X509GeneralName_(self, pvno, sender, recipient);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Integer:(LibOrgBouncycastleAsn1ASN1Integer *)pvno
                withLibOrgBouncycastleAsn1X509GeneralName:(LibOrgBouncycastleAsn1X509GeneralName *)sender
                withLibOrgBouncycastleAsn1X509GeneralName:(LibOrgBouncycastleAsn1X509GeneralName *)recipient {
  LibOrgBouncycastleAsn1CmpPKIHeader_initWithLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1X509GeneralName_withLibOrgBouncycastleAsn1X509GeneralName_(self, pvno, sender, recipient);
  return self;
}

- (LibOrgBouncycastleAsn1ASN1Integer *)getPvno {
  return pvno_;
}

- (LibOrgBouncycastleAsn1X509GeneralName *)getSender {
  return sender_;
}

- (LibOrgBouncycastleAsn1X509GeneralName *)getRecipient {
  return recipient_;
}

- (LibOrgBouncycastleAsn1ASN1GeneralizedTime *)getMessageTime {
  return messageTime_;
}

- (LibOrgBouncycastleAsn1X509AlgorithmIdentifier *)getProtectionAlg {
  return protectionAlg_;
}

- (LibOrgBouncycastleAsn1ASN1OctetString *)getSenderKID {
  return senderKID_;
}

- (LibOrgBouncycastleAsn1ASN1OctetString *)getRecipKID {
  return recipKID_;
}

- (LibOrgBouncycastleAsn1ASN1OctetString *)getTransactionID {
  return transactionID_;
}

- (LibOrgBouncycastleAsn1ASN1OctetString *)getSenderNonce {
  return senderNonce_;
}

- (LibOrgBouncycastleAsn1ASN1OctetString *)getRecipNonce {
  return recipNonce_;
}

- (LibOrgBouncycastleAsn1CmpPKIFreeText *)getFreeText {
  return freeText_;
}

- (IOSObjectArray *)getGeneralInfo {
  if (generalInfo_ == nil) {
    return nil;
  }
  IOSObjectArray *results = [IOSObjectArray newArrayWithLength:[generalInfo_ size] type:LibOrgBouncycastleAsn1CmpInfoTypeAndValue_class_()];
  for (jint i = 0; i < results->size_; i++) {
    (void) IOSObjectArray_Set(results, i, LibOrgBouncycastleAsn1CmpInfoTypeAndValue_getInstanceWithId_([((LibOrgBouncycastleAsn1ASN1Sequence *) nil_chk(generalInfo_)) getObjectAtWithInt:i]));
  }
  return results;
}

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive {
  LibOrgBouncycastleAsn1ASN1EncodableVector *v = new_LibOrgBouncycastleAsn1ASN1EncodableVector_init();
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:pvno_];
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:sender_];
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:recipient_];
  LibOrgBouncycastleAsn1CmpPKIHeader_addOptionalWithLibOrgBouncycastleAsn1ASN1EncodableVector_withInt_withLibOrgBouncycastleAsn1ASN1Encodable_(self, v, 0, messageTime_);
  LibOrgBouncycastleAsn1CmpPKIHeader_addOptionalWithLibOrgBouncycastleAsn1ASN1EncodableVector_withInt_withLibOrgBouncycastleAsn1ASN1Encodable_(self, v, 1, protectionAlg_);
  LibOrgBouncycastleAsn1CmpPKIHeader_addOptionalWithLibOrgBouncycastleAsn1ASN1EncodableVector_withInt_withLibOrgBouncycastleAsn1ASN1Encodable_(self, v, 2, senderKID_);
  LibOrgBouncycastleAsn1CmpPKIHeader_addOptionalWithLibOrgBouncycastleAsn1ASN1EncodableVector_withInt_withLibOrgBouncycastleAsn1ASN1Encodable_(self, v, 3, recipKID_);
  LibOrgBouncycastleAsn1CmpPKIHeader_addOptionalWithLibOrgBouncycastleAsn1ASN1EncodableVector_withInt_withLibOrgBouncycastleAsn1ASN1Encodable_(self, v, 4, transactionID_);
  LibOrgBouncycastleAsn1CmpPKIHeader_addOptionalWithLibOrgBouncycastleAsn1ASN1EncodableVector_withInt_withLibOrgBouncycastleAsn1ASN1Encodable_(self, v, 5, senderNonce_);
  LibOrgBouncycastleAsn1CmpPKIHeader_addOptionalWithLibOrgBouncycastleAsn1ASN1EncodableVector_withInt_withLibOrgBouncycastleAsn1ASN1Encodable_(self, v, 6, recipNonce_);
  LibOrgBouncycastleAsn1CmpPKIHeader_addOptionalWithLibOrgBouncycastleAsn1ASN1EncodableVector_withInt_withLibOrgBouncycastleAsn1ASN1Encodable_(self, v, 7, freeText_);
  LibOrgBouncycastleAsn1CmpPKIHeader_addOptionalWithLibOrgBouncycastleAsn1ASN1EncodableVector_withInt_withLibOrgBouncycastleAsn1ASN1Encodable_(self, v, 8, generalInfo_);
  return new_LibOrgBouncycastleAsn1DERSequence_initWithLibOrgBouncycastleAsn1ASN1EncodableVector_(v);
}

- (void)addOptionalWithLibOrgBouncycastleAsn1ASN1EncodableVector:(LibOrgBouncycastleAsn1ASN1EncodableVector *)v
                                                         withInt:(jint)tagNo
                         withLibOrgBouncycastleAsn1ASN1Encodable:(id<LibOrgBouncycastleAsn1ASN1Encodable>)obj {
  LibOrgBouncycastleAsn1CmpPKIHeader_addOptionalWithLibOrgBouncycastleAsn1ASN1EncodableVector_withInt_withLibOrgBouncycastleAsn1ASN1Encodable_(self, v, tagNo, obj);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x2, -1, 0, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1CmpPKIHeader;", 0x9, 1, 2, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 3, -1, -1, -1, -1 },
    { NULL, NULL, 0x2, -1, 4, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Integer;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1X509GeneralName;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1X509GeneralName;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1GeneralizedTime;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1X509AlgorithmIdentifier;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1OctetString;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1OctetString;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1OctetString;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1OctetString;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1OctetString;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1CmpPKIFreeText;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[LLibOrgBouncycastleAsn1CmpInfoTypeAndValue;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x2, 5, 6, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1Sequence:);
  methods[1].selector = @selector(getInstanceWithId:);
  methods[2].selector = @selector(initWithInt:withLibOrgBouncycastleAsn1X509GeneralName:withLibOrgBouncycastleAsn1X509GeneralName:);
  methods[3].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1Integer:withLibOrgBouncycastleAsn1X509GeneralName:withLibOrgBouncycastleAsn1X509GeneralName:);
  methods[4].selector = @selector(getPvno);
  methods[5].selector = @selector(getSender);
  methods[6].selector = @selector(getRecipient);
  methods[7].selector = @selector(getMessageTime);
  methods[8].selector = @selector(getProtectionAlg);
  methods[9].selector = @selector(getSenderKID);
  methods[10].selector = @selector(getRecipKID);
  methods[11].selector = @selector(getTransactionID);
  methods[12].selector = @selector(getSenderNonce);
  methods[13].selector = @selector(getRecipNonce);
  methods[14].selector = @selector(getFreeText);
  methods[15].selector = @selector(getGeneralInfo);
  methods[16].selector = @selector(toASN1Primitive);
  methods[17].selector = @selector(addOptionalWithLibOrgBouncycastleAsn1ASN1EncodableVector:withInt:withLibOrgBouncycastleAsn1ASN1Encodable:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "NULL_NAME", "LLibOrgBouncycastleAsn1X509GeneralName;", .constantValue.asLong = 0, 0x19, -1, 7, -1, -1 },
    { "CMP_1999", "I", .constantValue.asInt = LibOrgBouncycastleAsn1CmpPKIHeader_CMP_1999, 0x19, -1, -1, -1, -1 },
    { "CMP_2000", "I", .constantValue.asInt = LibOrgBouncycastleAsn1CmpPKIHeader_CMP_2000, 0x19, -1, -1, -1, -1 },
    { "pvno_", "LLibOrgBouncycastleAsn1ASN1Integer;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "sender_", "LLibOrgBouncycastleAsn1X509GeneralName;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "recipient_", "LLibOrgBouncycastleAsn1X509GeneralName;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "messageTime_", "LLibOrgBouncycastleAsn1ASN1GeneralizedTime;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "protectionAlg_", "LLibOrgBouncycastleAsn1X509AlgorithmIdentifier;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "senderKID_", "LLibOrgBouncycastleAsn1ASN1OctetString;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "recipKID_", "LLibOrgBouncycastleAsn1ASN1OctetString;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "transactionID_", "LLibOrgBouncycastleAsn1ASN1OctetString;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "senderNonce_", "LLibOrgBouncycastleAsn1ASN1OctetString;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "recipNonce_", "LLibOrgBouncycastleAsn1ASN1OctetString;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "freeText_", "LLibOrgBouncycastleAsn1CmpPKIFreeText;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "generalInfo_", "LLibOrgBouncycastleAsn1ASN1Sequence;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleAsn1ASN1Sequence;", "getInstance", "LNSObject;", "ILLibOrgBouncycastleAsn1X509GeneralName;LLibOrgBouncycastleAsn1X509GeneralName;", "LLibOrgBouncycastleAsn1ASN1Integer;LLibOrgBouncycastleAsn1X509GeneralName;LLibOrgBouncycastleAsn1X509GeneralName;", "addOptional", "LLibOrgBouncycastleAsn1ASN1EncodableVector;ILLibOrgBouncycastleAsn1ASN1Encodable;", &LibOrgBouncycastleAsn1CmpPKIHeader_NULL_NAME };
  static const J2ObjcClassInfo _LibOrgBouncycastleAsn1CmpPKIHeader = { "PKIHeader", "lib.org.bouncycastle.asn1.cmp", ptrTable, methods, fields, 7, 0x1, 18, 15, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleAsn1CmpPKIHeader;
}

+ (void)initialize {
  if (self == [LibOrgBouncycastleAsn1CmpPKIHeader class]) {
    LibOrgBouncycastleAsn1CmpPKIHeader_NULL_NAME = new_LibOrgBouncycastleAsn1X509GeneralName_initWithLibOrgBouncycastleAsn1X500X500Name_(LibOrgBouncycastleAsn1X500X500Name_getInstanceWithId_(new_LibOrgBouncycastleAsn1DERSequence_init()));
    J2OBJC_SET_INITIALIZED(LibOrgBouncycastleAsn1CmpPKIHeader)
  }
}

@end

void LibOrgBouncycastleAsn1CmpPKIHeader_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1CmpPKIHeader *self, LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  id<JavaUtilEnumeration> en = [((LibOrgBouncycastleAsn1ASN1Sequence *) nil_chk(seq)) getObjects];
  self->pvno_ = LibOrgBouncycastleAsn1ASN1Integer_getInstanceWithId_([((id<JavaUtilEnumeration>) nil_chk(en)) nextElement]);
  self->sender_ = LibOrgBouncycastleAsn1X509GeneralName_getInstanceWithId_([en nextElement]);
  self->recipient_ = LibOrgBouncycastleAsn1X509GeneralName_getInstanceWithId_([en nextElement]);
  while ([en hasMoreElements]) {
    LibOrgBouncycastleAsn1ASN1TaggedObject *tObj = (LibOrgBouncycastleAsn1ASN1TaggedObject *) cast_chk([en nextElement], [LibOrgBouncycastleAsn1ASN1TaggedObject class]);
    switch ([((LibOrgBouncycastleAsn1ASN1TaggedObject *) nil_chk(tObj)) getTagNo]) {
      case 0:
      self->messageTime_ = LibOrgBouncycastleAsn1ASN1GeneralizedTime_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(tObj, true);
      break;
      case 1:
      self->protectionAlg_ = LibOrgBouncycastleAsn1X509AlgorithmIdentifier_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(tObj, true);
      break;
      case 2:
      self->senderKID_ = LibOrgBouncycastleAsn1ASN1OctetString_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(tObj, true);
      break;
      case 3:
      self->recipKID_ = LibOrgBouncycastleAsn1ASN1OctetString_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(tObj, true);
      break;
      case 4:
      self->transactionID_ = LibOrgBouncycastleAsn1ASN1OctetString_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(tObj, true);
      break;
      case 5:
      self->senderNonce_ = LibOrgBouncycastleAsn1ASN1OctetString_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(tObj, true);
      break;
      case 6:
      self->recipNonce_ = LibOrgBouncycastleAsn1ASN1OctetString_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(tObj, true);
      break;
      case 7:
      self->freeText_ = LibOrgBouncycastleAsn1CmpPKIFreeText_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(tObj, true);
      break;
      case 8:
      self->generalInfo_ = LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(tObj, true);
      break;
      default:
      @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$I", @"unknown tag number: ", [tObj getTagNo]));
    }
  }
}

LibOrgBouncycastleAsn1CmpPKIHeader *new_LibOrgBouncycastleAsn1CmpPKIHeader_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1CmpPKIHeader, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

LibOrgBouncycastleAsn1CmpPKIHeader *create_LibOrgBouncycastleAsn1CmpPKIHeader_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1CmpPKIHeader, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

LibOrgBouncycastleAsn1CmpPKIHeader *LibOrgBouncycastleAsn1CmpPKIHeader_getInstanceWithId_(id o) {
  LibOrgBouncycastleAsn1CmpPKIHeader_initialize();
  if ([o isKindOfClass:[LibOrgBouncycastleAsn1CmpPKIHeader class]]) {
    return (LibOrgBouncycastleAsn1CmpPKIHeader *) o;
  }
  if (o != nil) {
    return new_LibOrgBouncycastleAsn1CmpPKIHeader_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithId_(o));
  }
  return nil;
}

void LibOrgBouncycastleAsn1CmpPKIHeader_initWithInt_withLibOrgBouncycastleAsn1X509GeneralName_withLibOrgBouncycastleAsn1X509GeneralName_(LibOrgBouncycastleAsn1CmpPKIHeader *self, jint pvno, LibOrgBouncycastleAsn1X509GeneralName *sender, LibOrgBouncycastleAsn1X509GeneralName *recipient) {
  LibOrgBouncycastleAsn1CmpPKIHeader_initWithLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1X509GeneralName_withLibOrgBouncycastleAsn1X509GeneralName_(self, new_LibOrgBouncycastleAsn1ASN1Integer_initWithLong_(pvno), sender, recipient);
}

LibOrgBouncycastleAsn1CmpPKIHeader *new_LibOrgBouncycastleAsn1CmpPKIHeader_initWithInt_withLibOrgBouncycastleAsn1X509GeneralName_withLibOrgBouncycastleAsn1X509GeneralName_(jint pvno, LibOrgBouncycastleAsn1X509GeneralName *sender, LibOrgBouncycastleAsn1X509GeneralName *recipient) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1CmpPKIHeader, initWithInt_withLibOrgBouncycastleAsn1X509GeneralName_withLibOrgBouncycastleAsn1X509GeneralName_, pvno, sender, recipient)
}

LibOrgBouncycastleAsn1CmpPKIHeader *create_LibOrgBouncycastleAsn1CmpPKIHeader_initWithInt_withLibOrgBouncycastleAsn1X509GeneralName_withLibOrgBouncycastleAsn1X509GeneralName_(jint pvno, LibOrgBouncycastleAsn1X509GeneralName *sender, LibOrgBouncycastleAsn1X509GeneralName *recipient) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1CmpPKIHeader, initWithInt_withLibOrgBouncycastleAsn1X509GeneralName_withLibOrgBouncycastleAsn1X509GeneralName_, pvno, sender, recipient)
}

void LibOrgBouncycastleAsn1CmpPKIHeader_initWithLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1X509GeneralName_withLibOrgBouncycastleAsn1X509GeneralName_(LibOrgBouncycastleAsn1CmpPKIHeader *self, LibOrgBouncycastleAsn1ASN1Integer *pvno, LibOrgBouncycastleAsn1X509GeneralName *sender, LibOrgBouncycastleAsn1X509GeneralName *recipient) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->pvno_ = pvno;
  self->sender_ = sender;
  self->recipient_ = recipient;
}

LibOrgBouncycastleAsn1CmpPKIHeader *new_LibOrgBouncycastleAsn1CmpPKIHeader_initWithLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1X509GeneralName_withLibOrgBouncycastleAsn1X509GeneralName_(LibOrgBouncycastleAsn1ASN1Integer *pvno, LibOrgBouncycastleAsn1X509GeneralName *sender, LibOrgBouncycastleAsn1X509GeneralName *recipient) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1CmpPKIHeader, initWithLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1X509GeneralName_withLibOrgBouncycastleAsn1X509GeneralName_, pvno, sender, recipient)
}

LibOrgBouncycastleAsn1CmpPKIHeader *create_LibOrgBouncycastleAsn1CmpPKIHeader_initWithLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1X509GeneralName_withLibOrgBouncycastleAsn1X509GeneralName_(LibOrgBouncycastleAsn1ASN1Integer *pvno, LibOrgBouncycastleAsn1X509GeneralName *sender, LibOrgBouncycastleAsn1X509GeneralName *recipient) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1CmpPKIHeader, initWithLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1X509GeneralName_withLibOrgBouncycastleAsn1X509GeneralName_, pvno, sender, recipient)
}

void LibOrgBouncycastleAsn1CmpPKIHeader_addOptionalWithLibOrgBouncycastleAsn1ASN1EncodableVector_withInt_withLibOrgBouncycastleAsn1ASN1Encodable_(LibOrgBouncycastleAsn1CmpPKIHeader *self, LibOrgBouncycastleAsn1ASN1EncodableVector *v, jint tagNo, id<LibOrgBouncycastleAsn1ASN1Encodable> obj) {
  if (obj != nil) {
    [((LibOrgBouncycastleAsn1ASN1EncodableVector *) nil_chk(v)) addWithLibOrgBouncycastleAsn1ASN1Encodable:new_LibOrgBouncycastleAsn1DERTaggedObject_initWithBoolean_withInt_withLibOrgBouncycastleAsn1ASN1Encodable_(true, tagNo, obj)];
  }
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleAsn1CmpPKIHeader)
