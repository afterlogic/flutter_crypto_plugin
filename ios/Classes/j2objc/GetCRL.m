//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/cmc/GetCRL.java
//

#include "ASN1Encodable.h"
#include "ASN1EncodableVector.h"
#include "ASN1GeneralizedTime.h"
#include "ASN1Object.h"
#include "ASN1Primitive.h"
#include "ASN1Sequence.h"
#include "ASN1TaggedObject.h"
#include "DERBitString.h"
#include "DERSequence.h"
#include "GeneralName.h"
#include "GetCRL.h"
#include "J2ObjC_source.h"
#include "ReasonFlags.h"
#include "X500Name.h"
#include "java/lang/IllegalArgumentException.h"

@interface LibOrgBouncycastleAsn1CmcGetCRL () {
 @public
  LibOrgBouncycastleAsn1X500X500Name *issuerName_;
  LibOrgBouncycastleAsn1X509GeneralName *cRLName_;
  LibOrgBouncycastleAsn1ASN1GeneralizedTime *time_;
  LibOrgBouncycastleAsn1X509ReasonFlags *reasons_;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1CmcGetCRL, issuerName_, LibOrgBouncycastleAsn1X500X500Name *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1CmcGetCRL, cRLName_, LibOrgBouncycastleAsn1X509GeneralName *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1CmcGetCRL, time_, LibOrgBouncycastleAsn1ASN1GeneralizedTime *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1CmcGetCRL, reasons_, LibOrgBouncycastleAsn1X509ReasonFlags *)

__attribute__((unused)) static void LibOrgBouncycastleAsn1CmcGetCRL_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1CmcGetCRL *self, LibOrgBouncycastleAsn1ASN1Sequence *seq);

__attribute__((unused)) static LibOrgBouncycastleAsn1CmcGetCRL *new_LibOrgBouncycastleAsn1CmcGetCRL_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleAsn1CmcGetCRL *create_LibOrgBouncycastleAsn1CmcGetCRL_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq);

@implementation LibOrgBouncycastleAsn1CmcGetCRL

- (instancetype)initWithLibOrgBouncycastleAsn1X500X500Name:(LibOrgBouncycastleAsn1X500X500Name *)issuerName
                 withLibOrgBouncycastleAsn1X509GeneralName:(LibOrgBouncycastleAsn1X509GeneralName *)cRLName
             withLibOrgBouncycastleAsn1ASN1GeneralizedTime:(LibOrgBouncycastleAsn1ASN1GeneralizedTime *)time
                 withLibOrgBouncycastleAsn1X509ReasonFlags:(LibOrgBouncycastleAsn1X509ReasonFlags *)reasons {
  LibOrgBouncycastleAsn1CmcGetCRL_initWithLibOrgBouncycastleAsn1X500X500Name_withLibOrgBouncycastleAsn1X509GeneralName_withLibOrgBouncycastleAsn1ASN1GeneralizedTime_withLibOrgBouncycastleAsn1X509ReasonFlags_(self, issuerName, cRLName, time, reasons);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq {
  LibOrgBouncycastleAsn1CmcGetCRL_initWithLibOrgBouncycastleAsn1ASN1Sequence_(self, seq);
  return self;
}

+ (LibOrgBouncycastleAsn1CmcGetCRL *)getInstanceWithId:(id)o {
  return LibOrgBouncycastleAsn1CmcGetCRL_getInstanceWithId_(o);
}

- (LibOrgBouncycastleAsn1X500X500Name *)getIssuerName {
  return issuerName_;
}

- (LibOrgBouncycastleAsn1X509GeneralName *)getcRLName {
  return cRLName_;
}

- (LibOrgBouncycastleAsn1ASN1GeneralizedTime *)getTime {
  return time_;
}

- (LibOrgBouncycastleAsn1X509ReasonFlags *)getReasons {
  return reasons_;
}

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive {
  LibOrgBouncycastleAsn1ASN1EncodableVector *v = new_LibOrgBouncycastleAsn1ASN1EncodableVector_init();
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:issuerName_];
  if (cRLName_ != nil) {
    [v addWithLibOrgBouncycastleAsn1ASN1Encodable:cRLName_];
  }
  if (time_ != nil) {
    [v addWithLibOrgBouncycastleAsn1ASN1Encodable:time_];
  }
  if (reasons_ != nil) {
    [v addWithLibOrgBouncycastleAsn1ASN1Encodable:reasons_];
  }
  return new_LibOrgBouncycastleAsn1DERSequence_initWithLibOrgBouncycastleAsn1ASN1EncodableVector_(v);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x2, -1, 1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1CmcGetCRL;", 0x9, 2, 3, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1X500X500Name;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1X509GeneralName;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1GeneralizedTime;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1X509ReasonFlags;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleAsn1X500X500Name:withLibOrgBouncycastleAsn1X509GeneralName:withLibOrgBouncycastleAsn1ASN1GeneralizedTime:withLibOrgBouncycastleAsn1X509ReasonFlags:);
  methods[1].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1Sequence:);
  methods[2].selector = @selector(getInstanceWithId:);
  methods[3].selector = @selector(getIssuerName);
  methods[4].selector = @selector(getcRLName);
  methods[5].selector = @selector(getTime);
  methods[6].selector = @selector(getReasons);
  methods[7].selector = @selector(toASN1Primitive);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "issuerName_", "LLibOrgBouncycastleAsn1X500X500Name;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "cRLName_", "LLibOrgBouncycastleAsn1X509GeneralName;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "time_", "LLibOrgBouncycastleAsn1ASN1GeneralizedTime;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "reasons_", "LLibOrgBouncycastleAsn1X509ReasonFlags;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleAsn1X500X500Name;LLibOrgBouncycastleAsn1X509GeneralName;LLibOrgBouncycastleAsn1ASN1GeneralizedTime;LLibOrgBouncycastleAsn1X509ReasonFlags;", "LLibOrgBouncycastleAsn1ASN1Sequence;", "getInstance", "LNSObject;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleAsn1CmcGetCRL = { "GetCRL", "lib.org.bouncycastle.asn1.cmc", ptrTable, methods, fields, 7, 0x1, 8, 4, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleAsn1CmcGetCRL;
}

@end

void LibOrgBouncycastleAsn1CmcGetCRL_initWithLibOrgBouncycastleAsn1X500X500Name_withLibOrgBouncycastleAsn1X509GeneralName_withLibOrgBouncycastleAsn1ASN1GeneralizedTime_withLibOrgBouncycastleAsn1X509ReasonFlags_(LibOrgBouncycastleAsn1CmcGetCRL *self, LibOrgBouncycastleAsn1X500X500Name *issuerName, LibOrgBouncycastleAsn1X509GeneralName *cRLName, LibOrgBouncycastleAsn1ASN1GeneralizedTime *time, LibOrgBouncycastleAsn1X509ReasonFlags *reasons) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->issuerName_ = issuerName;
  self->cRLName_ = cRLName;
  self->time_ = time;
  self->reasons_ = reasons;
}

LibOrgBouncycastleAsn1CmcGetCRL *new_LibOrgBouncycastleAsn1CmcGetCRL_initWithLibOrgBouncycastleAsn1X500X500Name_withLibOrgBouncycastleAsn1X509GeneralName_withLibOrgBouncycastleAsn1ASN1GeneralizedTime_withLibOrgBouncycastleAsn1X509ReasonFlags_(LibOrgBouncycastleAsn1X500X500Name *issuerName, LibOrgBouncycastleAsn1X509GeneralName *cRLName, LibOrgBouncycastleAsn1ASN1GeneralizedTime *time, LibOrgBouncycastleAsn1X509ReasonFlags *reasons) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1CmcGetCRL, initWithLibOrgBouncycastleAsn1X500X500Name_withLibOrgBouncycastleAsn1X509GeneralName_withLibOrgBouncycastleAsn1ASN1GeneralizedTime_withLibOrgBouncycastleAsn1X509ReasonFlags_, issuerName, cRLName, time, reasons)
}

LibOrgBouncycastleAsn1CmcGetCRL *create_LibOrgBouncycastleAsn1CmcGetCRL_initWithLibOrgBouncycastleAsn1X500X500Name_withLibOrgBouncycastleAsn1X509GeneralName_withLibOrgBouncycastleAsn1ASN1GeneralizedTime_withLibOrgBouncycastleAsn1X509ReasonFlags_(LibOrgBouncycastleAsn1X500X500Name *issuerName, LibOrgBouncycastleAsn1X509GeneralName *cRLName, LibOrgBouncycastleAsn1ASN1GeneralizedTime *time, LibOrgBouncycastleAsn1X509ReasonFlags *reasons) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1CmcGetCRL, initWithLibOrgBouncycastleAsn1X500X500Name_withLibOrgBouncycastleAsn1X509GeneralName_withLibOrgBouncycastleAsn1ASN1GeneralizedTime_withLibOrgBouncycastleAsn1X509ReasonFlags_, issuerName, cRLName, time, reasons)
}

void LibOrgBouncycastleAsn1CmcGetCRL_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1CmcGetCRL *self, LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  if ([((LibOrgBouncycastleAsn1ASN1Sequence *) nil_chk(seq)) size] < 1 || [seq size] > 4) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"incorrect sequence size");
  }
  self->issuerName_ = LibOrgBouncycastleAsn1X500X500Name_getInstanceWithId_([seq getObjectAtWithInt:0]);
  jint index = 1;
  if ([seq size] > index && [[((id<LibOrgBouncycastleAsn1ASN1Encodable>) nil_chk([seq getObjectAtWithInt:index])) toASN1Primitive] isKindOfClass:[LibOrgBouncycastleAsn1ASN1TaggedObject class]]) {
    self->cRLName_ = LibOrgBouncycastleAsn1X509GeneralName_getInstanceWithId_([seq getObjectAtWithInt:index++]);
  }
  if ([seq size] > index && [[((id<LibOrgBouncycastleAsn1ASN1Encodable>) nil_chk([seq getObjectAtWithInt:index])) toASN1Primitive] isKindOfClass:[LibOrgBouncycastleAsn1ASN1GeneralizedTime class]]) {
    self->time_ = LibOrgBouncycastleAsn1ASN1GeneralizedTime_getInstanceWithId_([seq getObjectAtWithInt:index++]);
  }
  if ([seq size] > index && [[((id<LibOrgBouncycastleAsn1ASN1Encodable>) nil_chk([seq getObjectAtWithInt:index])) toASN1Primitive] isKindOfClass:[LibOrgBouncycastleAsn1DERBitString class]]) {
    self->reasons_ = new_LibOrgBouncycastleAsn1X509ReasonFlags_initWithLibOrgBouncycastleAsn1DERBitString_(LibOrgBouncycastleAsn1DERBitString_getInstanceWithId_([seq getObjectAtWithInt:index]));
  }
}

LibOrgBouncycastleAsn1CmcGetCRL *new_LibOrgBouncycastleAsn1CmcGetCRL_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1CmcGetCRL, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

LibOrgBouncycastleAsn1CmcGetCRL *create_LibOrgBouncycastleAsn1CmcGetCRL_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1CmcGetCRL, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

LibOrgBouncycastleAsn1CmcGetCRL *LibOrgBouncycastleAsn1CmcGetCRL_getInstanceWithId_(id o) {
  LibOrgBouncycastleAsn1CmcGetCRL_initialize();
  if ([o isKindOfClass:[LibOrgBouncycastleAsn1CmcGetCRL class]]) {
    return (LibOrgBouncycastleAsn1CmcGetCRL *) o;
  }
  if (o != nil) {
    return new_LibOrgBouncycastleAsn1CmcGetCRL_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithId_(o));
  }
  return nil;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleAsn1CmcGetCRL)
