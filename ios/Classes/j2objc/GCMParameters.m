//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/cms/GCMParameters.java
//

#include "ASN1Encodable.h"
#include "ASN1EncodableVector.h"
#include "ASN1Integer.h"
#include "ASN1Object.h"
#include "ASN1OctetString.h"
#include "ASN1Primitive.h"
#include "ASN1Sequence.h"
#include "Arrays.h"
#include "DEROctetString.h"
#include "DERSequence.h"
#include "GCMParameters.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "java/math/BigInteger.h"

@interface LibOrgBouncycastleAsn1CmsGCMParameters () {
 @public
  IOSByteArray *nonce_;
  jint icvLen_;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1CmsGCMParameters, nonce_, IOSByteArray *)

__attribute__((unused)) static void LibOrgBouncycastleAsn1CmsGCMParameters_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1CmsGCMParameters *self, LibOrgBouncycastleAsn1ASN1Sequence *seq);

__attribute__((unused)) static LibOrgBouncycastleAsn1CmsGCMParameters *new_LibOrgBouncycastleAsn1CmsGCMParameters_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleAsn1CmsGCMParameters *create_LibOrgBouncycastleAsn1CmsGCMParameters_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq);

@implementation LibOrgBouncycastleAsn1CmsGCMParameters

+ (LibOrgBouncycastleAsn1CmsGCMParameters *)getInstanceWithId:(id)obj {
  return LibOrgBouncycastleAsn1CmsGCMParameters_getInstanceWithId_(obj);
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq {
  LibOrgBouncycastleAsn1CmsGCMParameters_initWithLibOrgBouncycastleAsn1ASN1Sequence_(self, seq);
  return self;
}

- (instancetype)initWithByteArray:(IOSByteArray *)nonce
                          withInt:(jint)icvLen {
  LibOrgBouncycastleAsn1CmsGCMParameters_initWithByteArray_withInt_(self, nonce, icvLen);
  return self;
}

- (IOSByteArray *)getNonce {
  return LibOrgBouncycastleUtilArrays_cloneWithByteArray_(nonce_);
}

- (jint)getIcvLen {
  return icvLen_;
}

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive {
  LibOrgBouncycastleAsn1ASN1EncodableVector *v = new_LibOrgBouncycastleAsn1ASN1EncodableVector_init();
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:new_LibOrgBouncycastleAsn1DEROctetString_initWithByteArray_(nonce_)];
  if (icvLen_ != 12) {
    [v addWithLibOrgBouncycastleAsn1ASN1Encodable:new_LibOrgBouncycastleAsn1ASN1Integer_initWithLong_(icvLen_)];
  }
  return new_LibOrgBouncycastleAsn1DERSequence_initWithLibOrgBouncycastleAsn1ASN1EncodableVector_(v);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, "LLibOrgBouncycastleAsn1CmsGCMParameters;", 0x9, 0, 1, -1, -1, -1, -1 },
    { NULL, NULL, 0x2, -1, 2, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 3, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(getInstanceWithId:);
  methods[1].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1Sequence:);
  methods[2].selector = @selector(initWithByteArray:withInt:);
  methods[3].selector = @selector(getNonce);
  methods[4].selector = @selector(getIcvLen);
  methods[5].selector = @selector(toASN1Primitive);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "nonce_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "icvLen_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "getInstance", "LNSObject;", "LLibOrgBouncycastleAsn1ASN1Sequence;", "[BI" };
  static const J2ObjcClassInfo _LibOrgBouncycastleAsn1CmsGCMParameters = { "GCMParameters", "lib.org.bouncycastle.asn1.cms", ptrTable, methods, fields, 7, 0x1, 6, 2, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleAsn1CmsGCMParameters;
}

@end

LibOrgBouncycastleAsn1CmsGCMParameters *LibOrgBouncycastleAsn1CmsGCMParameters_getInstanceWithId_(id obj) {
  LibOrgBouncycastleAsn1CmsGCMParameters_initialize();
  if ([obj isKindOfClass:[LibOrgBouncycastleAsn1CmsGCMParameters class]]) {
    return (LibOrgBouncycastleAsn1CmsGCMParameters *) obj;
  }
  else if (obj != nil) {
    return new_LibOrgBouncycastleAsn1CmsGCMParameters_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithId_(obj));
  }
  return nil;
}

void LibOrgBouncycastleAsn1CmsGCMParameters_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1CmsGCMParameters *self, LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->nonce_ = [((LibOrgBouncycastleAsn1ASN1OctetString *) nil_chk(LibOrgBouncycastleAsn1ASN1OctetString_getInstanceWithId_([((LibOrgBouncycastleAsn1ASN1Sequence *) nil_chk(seq)) getObjectAtWithInt:0]))) getOctets];
  if ([seq size] == 2) {
    self->icvLen_ = [((JavaMathBigInteger *) nil_chk([((LibOrgBouncycastleAsn1ASN1Integer *) nil_chk(LibOrgBouncycastleAsn1ASN1Integer_getInstanceWithId_([seq getObjectAtWithInt:1]))) getValue])) intValue];
  }
  else {
    self->icvLen_ = 12;
  }
}

LibOrgBouncycastleAsn1CmsGCMParameters *new_LibOrgBouncycastleAsn1CmsGCMParameters_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1CmsGCMParameters, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

LibOrgBouncycastleAsn1CmsGCMParameters *create_LibOrgBouncycastleAsn1CmsGCMParameters_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1CmsGCMParameters, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

void LibOrgBouncycastleAsn1CmsGCMParameters_initWithByteArray_withInt_(LibOrgBouncycastleAsn1CmsGCMParameters *self, IOSByteArray *nonce, jint icvLen) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->nonce_ = LibOrgBouncycastleUtilArrays_cloneWithByteArray_(nonce);
  self->icvLen_ = icvLen;
}

LibOrgBouncycastleAsn1CmsGCMParameters *new_LibOrgBouncycastleAsn1CmsGCMParameters_initWithByteArray_withInt_(IOSByteArray *nonce, jint icvLen) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1CmsGCMParameters, initWithByteArray_withInt_, nonce, icvLen)
}

LibOrgBouncycastleAsn1CmsGCMParameters *create_LibOrgBouncycastleAsn1CmsGCMParameters_initWithByteArray_withInt_(IOSByteArray *nonce, jint icvLen) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1CmsGCMParameters, initWithByteArray_withInt_, nonce, icvLen)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleAsn1CmsGCMParameters)
