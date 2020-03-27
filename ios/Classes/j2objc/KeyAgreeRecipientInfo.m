//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/cms/KeyAgreeRecipientInfo.java
//

#include "ASN1Encodable.h"
#include "ASN1EncodableVector.h"
#include "ASN1Integer.h"
#include "ASN1Object.h"
#include "ASN1OctetString.h"
#include "ASN1Primitive.h"
#include "ASN1Sequence.h"
#include "ASN1TaggedObject.h"
#include "AlgorithmIdentifier.h"
#include "DERSequence.h"
#include "DERTaggedObject.h"
#include "J2ObjC_source.h"
#include "KeyAgreeRecipientInfo.h"
#include "OriginatorIdentifierOrKey.h"

@interface LibOrgBouncycastleAsn1CmsKeyAgreeRecipientInfo () {
 @public
  LibOrgBouncycastleAsn1ASN1Integer *version__;
  LibOrgBouncycastleAsn1CmsOriginatorIdentifierOrKey *originator_;
  LibOrgBouncycastleAsn1ASN1OctetString *ukm_;
  LibOrgBouncycastleAsn1X509AlgorithmIdentifier *keyEncryptionAlgorithm_;
  LibOrgBouncycastleAsn1ASN1Sequence *recipientEncryptedKeys_;
}

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1CmsKeyAgreeRecipientInfo, version__, LibOrgBouncycastleAsn1ASN1Integer *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1CmsKeyAgreeRecipientInfo, originator_, LibOrgBouncycastleAsn1CmsOriginatorIdentifierOrKey *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1CmsKeyAgreeRecipientInfo, ukm_, LibOrgBouncycastleAsn1ASN1OctetString *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1CmsKeyAgreeRecipientInfo, keyEncryptionAlgorithm_, LibOrgBouncycastleAsn1X509AlgorithmIdentifier *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1CmsKeyAgreeRecipientInfo, recipientEncryptedKeys_, LibOrgBouncycastleAsn1ASN1Sequence *)

@implementation LibOrgBouncycastleAsn1CmsKeyAgreeRecipientInfo

- (instancetype)initWithLibOrgBouncycastleAsn1CmsOriginatorIdentifierOrKey:(LibOrgBouncycastleAsn1CmsOriginatorIdentifierOrKey *)originator
                                 withLibOrgBouncycastleAsn1ASN1OctetString:(LibOrgBouncycastleAsn1ASN1OctetString *)ukm
                         withLibOrgBouncycastleAsn1X509AlgorithmIdentifier:(LibOrgBouncycastleAsn1X509AlgorithmIdentifier *)keyEncryptionAlgorithm
                                    withLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)recipientEncryptedKeys {
  LibOrgBouncycastleAsn1CmsKeyAgreeRecipientInfo_initWithLibOrgBouncycastleAsn1CmsOriginatorIdentifierOrKey_withLibOrgBouncycastleAsn1ASN1OctetString_withLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withLibOrgBouncycastleAsn1ASN1Sequence_(self, originator, ukm, keyEncryptionAlgorithm, recipientEncryptedKeys);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq {
  LibOrgBouncycastleAsn1CmsKeyAgreeRecipientInfo_initWithLibOrgBouncycastleAsn1ASN1Sequence_(self, seq);
  return self;
}

+ (LibOrgBouncycastleAsn1CmsKeyAgreeRecipientInfo *)getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject:(LibOrgBouncycastleAsn1ASN1TaggedObject *)obj
                                                                                              withBoolean:(jboolean)explicit_ {
  return LibOrgBouncycastleAsn1CmsKeyAgreeRecipientInfo_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(obj, explicit_);
}

+ (LibOrgBouncycastleAsn1CmsKeyAgreeRecipientInfo *)getInstanceWithId:(id)obj {
  return LibOrgBouncycastleAsn1CmsKeyAgreeRecipientInfo_getInstanceWithId_(obj);
}

- (LibOrgBouncycastleAsn1ASN1Integer *)getVersion {
  return version__;
}

- (LibOrgBouncycastleAsn1CmsOriginatorIdentifierOrKey *)getOriginator {
  return originator_;
}

- (LibOrgBouncycastleAsn1ASN1OctetString *)getUserKeyingMaterial {
  return ukm_;
}

- (LibOrgBouncycastleAsn1X509AlgorithmIdentifier *)getKeyEncryptionAlgorithm {
  return keyEncryptionAlgorithm_;
}

- (LibOrgBouncycastleAsn1ASN1Sequence *)getRecipientEncryptedKeys {
  return recipientEncryptedKeys_;
}

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive {
  LibOrgBouncycastleAsn1ASN1EncodableVector *v = new_LibOrgBouncycastleAsn1ASN1EncodableVector_init();
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:version__];
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:new_LibOrgBouncycastleAsn1DERTaggedObject_initWithBoolean_withInt_withLibOrgBouncycastleAsn1ASN1Encodable_(true, 0, originator_)];
  if (ukm_ != nil) {
    [v addWithLibOrgBouncycastleAsn1ASN1Encodable:new_LibOrgBouncycastleAsn1DERTaggedObject_initWithBoolean_withInt_withLibOrgBouncycastleAsn1ASN1Encodable_(true, 1, ukm_)];
  }
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:keyEncryptionAlgorithm_];
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:recipientEncryptedKeys_];
  return new_LibOrgBouncycastleAsn1DERSequence_initWithLibOrgBouncycastleAsn1ASN1EncodableVector_(v);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1CmsKeyAgreeRecipientInfo;", 0x9, 2, 3, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1CmsKeyAgreeRecipientInfo;", 0x9, 2, 4, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Integer;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1CmsOriginatorIdentifierOrKey;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1OctetString;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1X509AlgorithmIdentifier;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Sequence;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleAsn1CmsOriginatorIdentifierOrKey:withLibOrgBouncycastleAsn1ASN1OctetString:withLibOrgBouncycastleAsn1X509AlgorithmIdentifier:withLibOrgBouncycastleAsn1ASN1Sequence:);
  methods[1].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1Sequence:);
  methods[2].selector = @selector(getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject:withBoolean:);
  methods[3].selector = @selector(getInstanceWithId:);
  methods[4].selector = @selector(getVersion);
  methods[5].selector = @selector(getOriginator);
  methods[6].selector = @selector(getUserKeyingMaterial);
  methods[7].selector = @selector(getKeyEncryptionAlgorithm);
  methods[8].selector = @selector(getRecipientEncryptedKeys);
  methods[9].selector = @selector(toASN1Primitive);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "version__", "LLibOrgBouncycastleAsn1ASN1Integer;", .constantValue.asLong = 0, 0x2, 5, -1, -1, -1 },
    { "originator_", "LLibOrgBouncycastleAsn1CmsOriginatorIdentifierOrKey;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "ukm_", "LLibOrgBouncycastleAsn1ASN1OctetString;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "keyEncryptionAlgorithm_", "LLibOrgBouncycastleAsn1X509AlgorithmIdentifier;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "recipientEncryptedKeys_", "LLibOrgBouncycastleAsn1ASN1Sequence;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleAsn1CmsOriginatorIdentifierOrKey;LLibOrgBouncycastleAsn1ASN1OctetString;LLibOrgBouncycastleAsn1X509AlgorithmIdentifier;LLibOrgBouncycastleAsn1ASN1Sequence;", "LLibOrgBouncycastleAsn1ASN1Sequence;", "getInstance", "LLibOrgBouncycastleAsn1ASN1TaggedObject;Z", "LNSObject;", "version" };
  static const J2ObjcClassInfo _LibOrgBouncycastleAsn1CmsKeyAgreeRecipientInfo = { "KeyAgreeRecipientInfo", "lib.org.bouncycastle.asn1.cms", ptrTable, methods, fields, 7, 0x1, 10, 5, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleAsn1CmsKeyAgreeRecipientInfo;
}

@end

void LibOrgBouncycastleAsn1CmsKeyAgreeRecipientInfo_initWithLibOrgBouncycastleAsn1CmsOriginatorIdentifierOrKey_withLibOrgBouncycastleAsn1ASN1OctetString_withLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1CmsKeyAgreeRecipientInfo *self, LibOrgBouncycastleAsn1CmsOriginatorIdentifierOrKey *originator, LibOrgBouncycastleAsn1ASN1OctetString *ukm, LibOrgBouncycastleAsn1X509AlgorithmIdentifier *keyEncryptionAlgorithm, LibOrgBouncycastleAsn1ASN1Sequence *recipientEncryptedKeys) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->version__ = new_LibOrgBouncycastleAsn1ASN1Integer_initWithLong_(3);
  self->originator_ = originator;
  self->ukm_ = ukm;
  self->keyEncryptionAlgorithm_ = keyEncryptionAlgorithm;
  self->recipientEncryptedKeys_ = recipientEncryptedKeys;
}

LibOrgBouncycastleAsn1CmsKeyAgreeRecipientInfo *new_LibOrgBouncycastleAsn1CmsKeyAgreeRecipientInfo_initWithLibOrgBouncycastleAsn1CmsOriginatorIdentifierOrKey_withLibOrgBouncycastleAsn1ASN1OctetString_withLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1CmsOriginatorIdentifierOrKey *originator, LibOrgBouncycastleAsn1ASN1OctetString *ukm, LibOrgBouncycastleAsn1X509AlgorithmIdentifier *keyEncryptionAlgorithm, LibOrgBouncycastleAsn1ASN1Sequence *recipientEncryptedKeys) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1CmsKeyAgreeRecipientInfo, initWithLibOrgBouncycastleAsn1CmsOriginatorIdentifierOrKey_withLibOrgBouncycastleAsn1ASN1OctetString_withLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withLibOrgBouncycastleAsn1ASN1Sequence_, originator, ukm, keyEncryptionAlgorithm, recipientEncryptedKeys)
}

LibOrgBouncycastleAsn1CmsKeyAgreeRecipientInfo *create_LibOrgBouncycastleAsn1CmsKeyAgreeRecipientInfo_initWithLibOrgBouncycastleAsn1CmsOriginatorIdentifierOrKey_withLibOrgBouncycastleAsn1ASN1OctetString_withLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1CmsOriginatorIdentifierOrKey *originator, LibOrgBouncycastleAsn1ASN1OctetString *ukm, LibOrgBouncycastleAsn1X509AlgorithmIdentifier *keyEncryptionAlgorithm, LibOrgBouncycastleAsn1ASN1Sequence *recipientEncryptedKeys) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1CmsKeyAgreeRecipientInfo, initWithLibOrgBouncycastleAsn1CmsOriginatorIdentifierOrKey_withLibOrgBouncycastleAsn1ASN1OctetString_withLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withLibOrgBouncycastleAsn1ASN1Sequence_, originator, ukm, keyEncryptionAlgorithm, recipientEncryptedKeys)
}

void LibOrgBouncycastleAsn1CmsKeyAgreeRecipientInfo_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1CmsKeyAgreeRecipientInfo *self, LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  jint index = 0;
  self->version__ = (LibOrgBouncycastleAsn1ASN1Integer *) cast_chk([((LibOrgBouncycastleAsn1ASN1Sequence *) nil_chk(seq)) getObjectAtWithInt:index++], [LibOrgBouncycastleAsn1ASN1Integer class]);
  self->originator_ = LibOrgBouncycastleAsn1CmsOriginatorIdentifierOrKey_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_((LibOrgBouncycastleAsn1ASN1TaggedObject *) cast_chk([seq getObjectAtWithInt:index++], [LibOrgBouncycastleAsn1ASN1TaggedObject class]), true);
  if ([[seq getObjectAtWithInt:index] isKindOfClass:[LibOrgBouncycastleAsn1ASN1TaggedObject class]]) {
    self->ukm_ = LibOrgBouncycastleAsn1ASN1OctetString_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_((LibOrgBouncycastleAsn1ASN1TaggedObject *) cast_chk([seq getObjectAtWithInt:index++], [LibOrgBouncycastleAsn1ASN1TaggedObject class]), true);
  }
  self->keyEncryptionAlgorithm_ = LibOrgBouncycastleAsn1X509AlgorithmIdentifier_getInstanceWithId_([seq getObjectAtWithInt:index++]);
  self->recipientEncryptedKeys_ = (LibOrgBouncycastleAsn1ASN1Sequence *) cast_chk([seq getObjectAtWithInt:index++], [LibOrgBouncycastleAsn1ASN1Sequence class]);
}

LibOrgBouncycastleAsn1CmsKeyAgreeRecipientInfo *new_LibOrgBouncycastleAsn1CmsKeyAgreeRecipientInfo_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1CmsKeyAgreeRecipientInfo, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

LibOrgBouncycastleAsn1CmsKeyAgreeRecipientInfo *create_LibOrgBouncycastleAsn1CmsKeyAgreeRecipientInfo_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1CmsKeyAgreeRecipientInfo, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

LibOrgBouncycastleAsn1CmsKeyAgreeRecipientInfo *LibOrgBouncycastleAsn1CmsKeyAgreeRecipientInfo_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(LibOrgBouncycastleAsn1ASN1TaggedObject *obj, jboolean explicit_) {
  LibOrgBouncycastleAsn1CmsKeyAgreeRecipientInfo_initialize();
  return LibOrgBouncycastleAsn1CmsKeyAgreeRecipientInfo_getInstanceWithId_(LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(obj, explicit_));
}

LibOrgBouncycastleAsn1CmsKeyAgreeRecipientInfo *LibOrgBouncycastleAsn1CmsKeyAgreeRecipientInfo_getInstanceWithId_(id obj) {
  LibOrgBouncycastleAsn1CmsKeyAgreeRecipientInfo_initialize();
  if ([obj isKindOfClass:[LibOrgBouncycastleAsn1CmsKeyAgreeRecipientInfo class]]) {
    return (LibOrgBouncycastleAsn1CmsKeyAgreeRecipientInfo *) obj;
  }
  if (obj != nil) {
    return new_LibOrgBouncycastleAsn1CmsKeyAgreeRecipientInfo_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithId_(obj));
  }
  return nil;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleAsn1CmsKeyAgreeRecipientInfo)