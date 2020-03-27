//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/crmf/CertReqMsg.java
//

#include "ASN1Encodable.h"
#include "ASN1EncodableVector.h"
#include "ASN1Object.h"
#include "ASN1Primitive.h"
#include "ASN1Sequence.h"
#include "ASN1TaggedObject.h"
#include "CertReqMsg.h"
#include "CertRequest.h"
#include "CrmfAttributeTypeAndValue.h"
#include "DERSequence.h"
#include "IOSClass.h"
#include "IOSObjectArray.h"
#include "J2ObjC_source.h"
#include "ProofOfPossession.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/util/Enumeration.h"

@interface LibOrgBouncycastleAsn1CrmfCertReqMsg () {
 @public
  LibOrgBouncycastleAsn1CrmfCertRequest *certReq_;
  LibOrgBouncycastleAsn1CrmfProofOfPossession *pop_;
  LibOrgBouncycastleAsn1ASN1Sequence *regInfo_;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq;

- (void)addOptionalWithLibOrgBouncycastleAsn1ASN1EncodableVector:(LibOrgBouncycastleAsn1ASN1EncodableVector *)v
                         withLibOrgBouncycastleAsn1ASN1Encodable:(id<LibOrgBouncycastleAsn1ASN1Encodable>)obj;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1CrmfCertReqMsg, certReq_, LibOrgBouncycastleAsn1CrmfCertRequest *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1CrmfCertReqMsg, pop_, LibOrgBouncycastleAsn1CrmfProofOfPossession *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1CrmfCertReqMsg, regInfo_, LibOrgBouncycastleAsn1ASN1Sequence *)

__attribute__((unused)) static void LibOrgBouncycastleAsn1CrmfCertReqMsg_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1CrmfCertReqMsg *self, LibOrgBouncycastleAsn1ASN1Sequence *seq);

__attribute__((unused)) static LibOrgBouncycastleAsn1CrmfCertReqMsg *new_LibOrgBouncycastleAsn1CrmfCertReqMsg_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleAsn1CrmfCertReqMsg *create_LibOrgBouncycastleAsn1CrmfCertReqMsg_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq);

__attribute__((unused)) static void LibOrgBouncycastleAsn1CrmfCertReqMsg_addOptionalWithLibOrgBouncycastleAsn1ASN1EncodableVector_withLibOrgBouncycastleAsn1ASN1Encodable_(LibOrgBouncycastleAsn1CrmfCertReqMsg *self, LibOrgBouncycastleAsn1ASN1EncodableVector *v, id<LibOrgBouncycastleAsn1ASN1Encodable> obj);

@implementation LibOrgBouncycastleAsn1CrmfCertReqMsg

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq {
  LibOrgBouncycastleAsn1CrmfCertReqMsg_initWithLibOrgBouncycastleAsn1ASN1Sequence_(self, seq);
  return self;
}

+ (LibOrgBouncycastleAsn1CrmfCertReqMsg *)getInstanceWithId:(id)o {
  return LibOrgBouncycastleAsn1CrmfCertReqMsg_getInstanceWithId_(o);
}

+ (LibOrgBouncycastleAsn1CrmfCertReqMsg *)getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject:(LibOrgBouncycastleAsn1ASN1TaggedObject *)obj
                                                                                    withBoolean:(jboolean)explicit_ {
  return LibOrgBouncycastleAsn1CrmfCertReqMsg_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(obj, explicit_);
}

- (instancetype)initWithLibOrgBouncycastleAsn1CrmfCertRequest:(LibOrgBouncycastleAsn1CrmfCertRequest *)certReq
              withLibOrgBouncycastleAsn1CrmfProofOfPossession:(LibOrgBouncycastleAsn1CrmfProofOfPossession *)pop
 withLibOrgBouncycastleAsn1CrmfCrmfAttributeTypeAndValueArray:(IOSObjectArray *)regInfo {
  LibOrgBouncycastleAsn1CrmfCertReqMsg_initWithLibOrgBouncycastleAsn1CrmfCertRequest_withLibOrgBouncycastleAsn1CrmfProofOfPossession_withLibOrgBouncycastleAsn1CrmfCrmfAttributeTypeAndValueArray_(self, certReq, pop, regInfo);
  return self;
}

- (LibOrgBouncycastleAsn1CrmfCertRequest *)getCertReq {
  return certReq_;
}

- (LibOrgBouncycastleAsn1CrmfProofOfPossession *)getPop {
  return pop_;
}

- (LibOrgBouncycastleAsn1CrmfProofOfPossession *)getPopo {
  return pop_;
}

- (IOSObjectArray *)getRegInfo {
  if (regInfo_ == nil) {
    return nil;
  }
  IOSObjectArray *results = [IOSObjectArray newArrayWithLength:[regInfo_ size] type:LibOrgBouncycastleAsn1CrmfCrmfAttributeTypeAndValue_class_()];
  for (jint i = 0; i != results->size_; i++) {
    (void) IOSObjectArray_Set(results, i, LibOrgBouncycastleAsn1CrmfCrmfAttributeTypeAndValue_getInstanceWithId_([((LibOrgBouncycastleAsn1ASN1Sequence *) nil_chk(regInfo_)) getObjectAtWithInt:i]));
  }
  return results;
}

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive {
  LibOrgBouncycastleAsn1ASN1EncodableVector *v = new_LibOrgBouncycastleAsn1ASN1EncodableVector_init();
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:certReq_];
  LibOrgBouncycastleAsn1CrmfCertReqMsg_addOptionalWithLibOrgBouncycastleAsn1ASN1EncodableVector_withLibOrgBouncycastleAsn1ASN1Encodable_(self, v, pop_);
  LibOrgBouncycastleAsn1CrmfCertReqMsg_addOptionalWithLibOrgBouncycastleAsn1ASN1EncodableVector_withLibOrgBouncycastleAsn1ASN1Encodable_(self, v, regInfo_);
  return new_LibOrgBouncycastleAsn1DERSequence_initWithLibOrgBouncycastleAsn1ASN1EncodableVector_(v);
}

- (void)addOptionalWithLibOrgBouncycastleAsn1ASN1EncodableVector:(LibOrgBouncycastleAsn1ASN1EncodableVector *)v
                         withLibOrgBouncycastleAsn1ASN1Encodable:(id<LibOrgBouncycastleAsn1ASN1Encodable>)obj {
  LibOrgBouncycastleAsn1CrmfCertReqMsg_addOptionalWithLibOrgBouncycastleAsn1ASN1EncodableVector_withLibOrgBouncycastleAsn1ASN1Encodable_(self, v, obj);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x2, -1, 0, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1CrmfCertReqMsg;", 0x9, 1, 2, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1CrmfCertReqMsg;", 0x9, 1, 3, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 4, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1CrmfCertRequest;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1CrmfProofOfPossession;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1CrmfProofOfPossession;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[LLibOrgBouncycastleAsn1CrmfCrmfAttributeTypeAndValue;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x2, 5, 6, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1Sequence:);
  methods[1].selector = @selector(getInstanceWithId:);
  methods[2].selector = @selector(getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject:withBoolean:);
  methods[3].selector = @selector(initWithLibOrgBouncycastleAsn1CrmfCertRequest:withLibOrgBouncycastleAsn1CrmfProofOfPossession:withLibOrgBouncycastleAsn1CrmfCrmfAttributeTypeAndValueArray:);
  methods[4].selector = @selector(getCertReq);
  methods[5].selector = @selector(getPop);
  methods[6].selector = @selector(getPopo);
  methods[7].selector = @selector(getRegInfo);
  methods[8].selector = @selector(toASN1Primitive);
  methods[9].selector = @selector(addOptionalWithLibOrgBouncycastleAsn1ASN1EncodableVector:withLibOrgBouncycastleAsn1ASN1Encodable:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "certReq_", "LLibOrgBouncycastleAsn1CrmfCertRequest;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "pop_", "LLibOrgBouncycastleAsn1CrmfProofOfPossession;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "regInfo_", "LLibOrgBouncycastleAsn1ASN1Sequence;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleAsn1ASN1Sequence;", "getInstance", "LNSObject;", "LLibOrgBouncycastleAsn1ASN1TaggedObject;Z", "LLibOrgBouncycastleAsn1CrmfCertRequest;LLibOrgBouncycastleAsn1CrmfProofOfPossession;[LLibOrgBouncycastleAsn1CrmfCrmfAttributeTypeAndValue;", "addOptional", "LLibOrgBouncycastleAsn1ASN1EncodableVector;LLibOrgBouncycastleAsn1ASN1Encodable;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleAsn1CrmfCertReqMsg = { "CertReqMsg", "lib.org.bouncycastle.asn1.crmf", ptrTable, methods, fields, 7, 0x1, 10, 3, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleAsn1CrmfCertReqMsg;
}

@end

void LibOrgBouncycastleAsn1CrmfCertReqMsg_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1CrmfCertReqMsg *self, LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  id<JavaUtilEnumeration> en = [((LibOrgBouncycastleAsn1ASN1Sequence *) nil_chk(seq)) getObjects];
  self->certReq_ = LibOrgBouncycastleAsn1CrmfCertRequest_getInstanceWithId_([((id<JavaUtilEnumeration>) nil_chk(en)) nextElement]);
  while ([en hasMoreElements]) {
    id o = [en nextElement];
    if ([o isKindOfClass:[LibOrgBouncycastleAsn1ASN1TaggedObject class]] || [o isKindOfClass:[LibOrgBouncycastleAsn1CrmfProofOfPossession class]]) {
      self->pop_ = LibOrgBouncycastleAsn1CrmfProofOfPossession_getInstanceWithId_(o);
    }
    else {
      self->regInfo_ = LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithId_(o);
    }
  }
}

LibOrgBouncycastleAsn1CrmfCertReqMsg *new_LibOrgBouncycastleAsn1CrmfCertReqMsg_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1CrmfCertReqMsg, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

LibOrgBouncycastleAsn1CrmfCertReqMsg *create_LibOrgBouncycastleAsn1CrmfCertReqMsg_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1CrmfCertReqMsg, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

LibOrgBouncycastleAsn1CrmfCertReqMsg *LibOrgBouncycastleAsn1CrmfCertReqMsg_getInstanceWithId_(id o) {
  LibOrgBouncycastleAsn1CrmfCertReqMsg_initialize();
  if ([o isKindOfClass:[LibOrgBouncycastleAsn1CrmfCertReqMsg class]]) {
    return (LibOrgBouncycastleAsn1CrmfCertReqMsg *) o;
  }
  else if (o != nil) {
    return new_LibOrgBouncycastleAsn1CrmfCertReqMsg_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithId_(o));
  }
  return nil;
}

LibOrgBouncycastleAsn1CrmfCertReqMsg *LibOrgBouncycastleAsn1CrmfCertReqMsg_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(LibOrgBouncycastleAsn1ASN1TaggedObject *obj, jboolean explicit_) {
  LibOrgBouncycastleAsn1CrmfCertReqMsg_initialize();
  return LibOrgBouncycastleAsn1CrmfCertReqMsg_getInstanceWithId_(LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(obj, explicit_));
}

void LibOrgBouncycastleAsn1CrmfCertReqMsg_initWithLibOrgBouncycastleAsn1CrmfCertRequest_withLibOrgBouncycastleAsn1CrmfProofOfPossession_withLibOrgBouncycastleAsn1CrmfCrmfAttributeTypeAndValueArray_(LibOrgBouncycastleAsn1CrmfCertReqMsg *self, LibOrgBouncycastleAsn1CrmfCertRequest *certReq, LibOrgBouncycastleAsn1CrmfProofOfPossession *pop, IOSObjectArray *regInfo) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  if (certReq == nil) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"'certReq' cannot be null");
  }
  self->certReq_ = certReq;
  self->pop_ = pop;
  if (regInfo != nil) {
    self->regInfo_ = new_LibOrgBouncycastleAsn1DERSequence_initWithLibOrgBouncycastleAsn1ASN1EncodableArray_(regInfo);
  }
}

LibOrgBouncycastleAsn1CrmfCertReqMsg *new_LibOrgBouncycastleAsn1CrmfCertReqMsg_initWithLibOrgBouncycastleAsn1CrmfCertRequest_withLibOrgBouncycastleAsn1CrmfProofOfPossession_withLibOrgBouncycastleAsn1CrmfCrmfAttributeTypeAndValueArray_(LibOrgBouncycastleAsn1CrmfCertRequest *certReq, LibOrgBouncycastleAsn1CrmfProofOfPossession *pop, IOSObjectArray *regInfo) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1CrmfCertReqMsg, initWithLibOrgBouncycastleAsn1CrmfCertRequest_withLibOrgBouncycastleAsn1CrmfProofOfPossession_withLibOrgBouncycastleAsn1CrmfCrmfAttributeTypeAndValueArray_, certReq, pop, regInfo)
}

LibOrgBouncycastleAsn1CrmfCertReqMsg *create_LibOrgBouncycastleAsn1CrmfCertReqMsg_initWithLibOrgBouncycastleAsn1CrmfCertRequest_withLibOrgBouncycastleAsn1CrmfProofOfPossession_withLibOrgBouncycastleAsn1CrmfCrmfAttributeTypeAndValueArray_(LibOrgBouncycastleAsn1CrmfCertRequest *certReq, LibOrgBouncycastleAsn1CrmfProofOfPossession *pop, IOSObjectArray *regInfo) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1CrmfCertReqMsg, initWithLibOrgBouncycastleAsn1CrmfCertRequest_withLibOrgBouncycastleAsn1CrmfProofOfPossession_withLibOrgBouncycastleAsn1CrmfCrmfAttributeTypeAndValueArray_, certReq, pop, regInfo)
}

void LibOrgBouncycastleAsn1CrmfCertReqMsg_addOptionalWithLibOrgBouncycastleAsn1ASN1EncodableVector_withLibOrgBouncycastleAsn1ASN1Encodable_(LibOrgBouncycastleAsn1CrmfCertReqMsg *self, LibOrgBouncycastleAsn1ASN1EncodableVector *v, id<LibOrgBouncycastleAsn1ASN1Encodable> obj) {
  if (obj != nil) {
    [((LibOrgBouncycastleAsn1ASN1EncodableVector *) nil_chk(v)) addWithLibOrgBouncycastleAsn1ASN1Encodable:obj];
  }
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleAsn1CrmfCertReqMsg)
