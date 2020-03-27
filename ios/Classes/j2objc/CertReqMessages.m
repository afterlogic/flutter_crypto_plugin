//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/crmf/CertReqMessages.java
//

#include "ASN1Encodable.h"
#include "ASN1EncodableVector.h"
#include "ASN1Object.h"
#include "ASN1Primitive.h"
#include "ASN1Sequence.h"
#include "CertReqMessages.h"
#include "CertReqMsg.h"
#include "DERSequence.h"
#include "IOSClass.h"
#include "IOSObjectArray.h"
#include "J2ObjC_source.h"

@interface LibOrgBouncycastleAsn1CrmfCertReqMessages () {
 @public
  LibOrgBouncycastleAsn1ASN1Sequence *content_;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1CrmfCertReqMessages, content_, LibOrgBouncycastleAsn1ASN1Sequence *)

__attribute__((unused)) static void LibOrgBouncycastleAsn1CrmfCertReqMessages_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1CrmfCertReqMessages *self, LibOrgBouncycastleAsn1ASN1Sequence *seq);

__attribute__((unused)) static LibOrgBouncycastleAsn1CrmfCertReqMessages *new_LibOrgBouncycastleAsn1CrmfCertReqMessages_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleAsn1CrmfCertReqMessages *create_LibOrgBouncycastleAsn1CrmfCertReqMessages_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq);

@implementation LibOrgBouncycastleAsn1CrmfCertReqMessages

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq {
  LibOrgBouncycastleAsn1CrmfCertReqMessages_initWithLibOrgBouncycastleAsn1ASN1Sequence_(self, seq);
  return self;
}

+ (LibOrgBouncycastleAsn1CrmfCertReqMessages *)getInstanceWithId:(id)o {
  return LibOrgBouncycastleAsn1CrmfCertReqMessages_getInstanceWithId_(o);
}

- (instancetype)initWithLibOrgBouncycastleAsn1CrmfCertReqMsg:(LibOrgBouncycastleAsn1CrmfCertReqMsg *)msg {
  LibOrgBouncycastleAsn1CrmfCertReqMessages_initWithLibOrgBouncycastleAsn1CrmfCertReqMsg_(self, msg);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleAsn1CrmfCertReqMsgArray:(IOSObjectArray *)msgs {
  LibOrgBouncycastleAsn1CrmfCertReqMessages_initWithLibOrgBouncycastleAsn1CrmfCertReqMsgArray_(self, msgs);
  return self;
}

- (IOSObjectArray *)toCertReqMsgArray {
  IOSObjectArray *result = [IOSObjectArray newArrayWithLength:[((LibOrgBouncycastleAsn1ASN1Sequence *) nil_chk(content_)) size] type:LibOrgBouncycastleAsn1CrmfCertReqMsg_class_()];
  for (jint i = 0; i != result->size_; i++) {
    (void) IOSObjectArray_Set(result, i, LibOrgBouncycastleAsn1CrmfCertReqMsg_getInstanceWithId_([((LibOrgBouncycastleAsn1ASN1Sequence *) nil_chk(content_)) getObjectAtWithInt:i]));
  }
  return result;
}

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive {
  return content_;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x2, -1, 0, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1CrmfCertReqMessages;", 0x9, 1, 2, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 3, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 4, -1, -1, -1, -1 },
    { NULL, "[LLibOrgBouncycastleAsn1CrmfCertReqMsg;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1Sequence:);
  methods[1].selector = @selector(getInstanceWithId:);
  methods[2].selector = @selector(initWithLibOrgBouncycastleAsn1CrmfCertReqMsg:);
  methods[3].selector = @selector(initWithLibOrgBouncycastleAsn1CrmfCertReqMsgArray:);
  methods[4].selector = @selector(toCertReqMsgArray);
  methods[5].selector = @selector(toASN1Primitive);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "content_", "LLibOrgBouncycastleAsn1ASN1Sequence;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleAsn1ASN1Sequence;", "getInstance", "LNSObject;", "LLibOrgBouncycastleAsn1CrmfCertReqMsg;", "[LLibOrgBouncycastleAsn1CrmfCertReqMsg;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleAsn1CrmfCertReqMessages = { "CertReqMessages", "lib.org.bouncycastle.asn1.crmf", ptrTable, methods, fields, 7, 0x1, 6, 1, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleAsn1CrmfCertReqMessages;
}

@end

void LibOrgBouncycastleAsn1CrmfCertReqMessages_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1CrmfCertReqMessages *self, LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->content_ = seq;
}

LibOrgBouncycastleAsn1CrmfCertReqMessages *new_LibOrgBouncycastleAsn1CrmfCertReqMessages_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1CrmfCertReqMessages, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

LibOrgBouncycastleAsn1CrmfCertReqMessages *create_LibOrgBouncycastleAsn1CrmfCertReqMessages_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1CrmfCertReqMessages, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

LibOrgBouncycastleAsn1CrmfCertReqMessages *LibOrgBouncycastleAsn1CrmfCertReqMessages_getInstanceWithId_(id o) {
  LibOrgBouncycastleAsn1CrmfCertReqMessages_initialize();
  if ([o isKindOfClass:[LibOrgBouncycastleAsn1CrmfCertReqMessages class]]) {
    return (LibOrgBouncycastleAsn1CrmfCertReqMessages *) o;
  }
  if (o != nil) {
    return new_LibOrgBouncycastleAsn1CrmfCertReqMessages_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithId_(o));
  }
  return nil;
}

void LibOrgBouncycastleAsn1CrmfCertReqMessages_initWithLibOrgBouncycastleAsn1CrmfCertReqMsg_(LibOrgBouncycastleAsn1CrmfCertReqMessages *self, LibOrgBouncycastleAsn1CrmfCertReqMsg *msg) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->content_ = new_LibOrgBouncycastleAsn1DERSequence_initWithLibOrgBouncycastleAsn1ASN1Encodable_(msg);
}

LibOrgBouncycastleAsn1CrmfCertReqMessages *new_LibOrgBouncycastleAsn1CrmfCertReqMessages_initWithLibOrgBouncycastleAsn1CrmfCertReqMsg_(LibOrgBouncycastleAsn1CrmfCertReqMsg *msg) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1CrmfCertReqMessages, initWithLibOrgBouncycastleAsn1CrmfCertReqMsg_, msg)
}

LibOrgBouncycastleAsn1CrmfCertReqMessages *create_LibOrgBouncycastleAsn1CrmfCertReqMessages_initWithLibOrgBouncycastleAsn1CrmfCertReqMsg_(LibOrgBouncycastleAsn1CrmfCertReqMsg *msg) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1CrmfCertReqMessages, initWithLibOrgBouncycastleAsn1CrmfCertReqMsg_, msg)
}

void LibOrgBouncycastleAsn1CrmfCertReqMessages_initWithLibOrgBouncycastleAsn1CrmfCertReqMsgArray_(LibOrgBouncycastleAsn1CrmfCertReqMessages *self, IOSObjectArray *msgs) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  LibOrgBouncycastleAsn1ASN1EncodableVector *v = new_LibOrgBouncycastleAsn1ASN1EncodableVector_init();
  for (jint i = 0; i < ((IOSObjectArray *) nil_chk(msgs))->size_; i++) {
    [v addWithLibOrgBouncycastleAsn1ASN1Encodable:IOSObjectArray_Get(msgs, i)];
  }
  self->content_ = new_LibOrgBouncycastleAsn1DERSequence_initWithLibOrgBouncycastleAsn1ASN1EncodableVector_(v);
}

LibOrgBouncycastleAsn1CrmfCertReqMessages *new_LibOrgBouncycastleAsn1CrmfCertReqMessages_initWithLibOrgBouncycastleAsn1CrmfCertReqMsgArray_(IOSObjectArray *msgs) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1CrmfCertReqMessages, initWithLibOrgBouncycastleAsn1CrmfCertReqMsgArray_, msgs)
}

LibOrgBouncycastleAsn1CrmfCertReqMessages *create_LibOrgBouncycastleAsn1CrmfCertReqMessages_initWithLibOrgBouncycastleAsn1CrmfCertReqMsgArray_(IOSObjectArray *msgs) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1CrmfCertReqMessages, initWithLibOrgBouncycastleAsn1CrmfCertReqMsgArray_, msgs)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleAsn1CrmfCertReqMessages)