//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/x509/CertificatePair.java
//

#include "ASN1EncodableVector.h"
#include "ASN1Object.h"
#include "ASN1Primitive.h"
#include "ASN1Sequence.h"
#include "ASN1TaggedObject.h"
#include "CertificatePair.h"
#include "DERSequence.h"
#include "DERTaggedObject.h"
#include "IOSClass.h"
#include "J2ObjC_source.h"
#include "X509Certificate.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/util/Enumeration.h"

@interface LibOrgBouncycastleAsn1X509CertificatePair () {
 @public
  LibOrgBouncycastleAsn1X509X509Certificate *forward_;
  LibOrgBouncycastleAsn1X509X509Certificate *reverse_;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1X509CertificatePair, forward_, LibOrgBouncycastleAsn1X509X509Certificate *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1X509CertificatePair, reverse_, LibOrgBouncycastleAsn1X509X509Certificate *)

__attribute__((unused)) static void LibOrgBouncycastleAsn1X509CertificatePair_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1X509CertificatePair *self, LibOrgBouncycastleAsn1ASN1Sequence *seq);

__attribute__((unused)) static LibOrgBouncycastleAsn1X509CertificatePair *new_LibOrgBouncycastleAsn1X509CertificatePair_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleAsn1X509CertificatePair *create_LibOrgBouncycastleAsn1X509CertificatePair_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq);

@implementation LibOrgBouncycastleAsn1X509CertificatePair

+ (LibOrgBouncycastleAsn1X509CertificatePair *)getInstanceWithId:(id)obj {
  return LibOrgBouncycastleAsn1X509CertificatePair_getInstanceWithId_(obj);
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq {
  LibOrgBouncycastleAsn1X509CertificatePair_initWithLibOrgBouncycastleAsn1ASN1Sequence_(self, seq);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleAsn1X509X509Certificate:(LibOrgBouncycastleAsn1X509X509Certificate *)forward
                    withLibOrgBouncycastleAsn1X509X509Certificate:(LibOrgBouncycastleAsn1X509X509Certificate *)reverse {
  LibOrgBouncycastleAsn1X509CertificatePair_initWithLibOrgBouncycastleAsn1X509X509Certificate_withLibOrgBouncycastleAsn1X509X509Certificate_(self, forward, reverse);
  return self;
}

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive {
  LibOrgBouncycastleAsn1ASN1EncodableVector *vec = new_LibOrgBouncycastleAsn1ASN1EncodableVector_init();
  if (forward_ != nil) {
    [vec addWithLibOrgBouncycastleAsn1ASN1Encodable:new_LibOrgBouncycastleAsn1DERTaggedObject_initWithInt_withLibOrgBouncycastleAsn1ASN1Encodable_(0, forward_)];
  }
  if (reverse_ != nil) {
    [vec addWithLibOrgBouncycastleAsn1ASN1Encodable:new_LibOrgBouncycastleAsn1DERTaggedObject_initWithInt_withLibOrgBouncycastleAsn1ASN1Encodable_(1, reverse_)];
  }
  return new_LibOrgBouncycastleAsn1DERSequence_initWithLibOrgBouncycastleAsn1ASN1EncodableVector_(vec);
}

- (LibOrgBouncycastleAsn1X509X509Certificate *)getForward {
  return forward_;
}

- (LibOrgBouncycastleAsn1X509X509Certificate *)getReverse {
  return reverse_;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, "LLibOrgBouncycastleAsn1X509CertificatePair;", 0x9, 0, 1, -1, -1, -1, -1 },
    { NULL, NULL, 0x2, -1, 2, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 3, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1X509X509Certificate;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1X509X509Certificate;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(getInstanceWithId:);
  methods[1].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1Sequence:);
  methods[2].selector = @selector(initWithLibOrgBouncycastleAsn1X509X509Certificate:withLibOrgBouncycastleAsn1X509X509Certificate:);
  methods[3].selector = @selector(toASN1Primitive);
  methods[4].selector = @selector(getForward);
  methods[5].selector = @selector(getReverse);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "forward_", "LLibOrgBouncycastleAsn1X509X509Certificate;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "reverse_", "LLibOrgBouncycastleAsn1X509X509Certificate;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "getInstance", "LNSObject;", "LLibOrgBouncycastleAsn1ASN1Sequence;", "LLibOrgBouncycastleAsn1X509X509Certificate;LLibOrgBouncycastleAsn1X509X509Certificate;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleAsn1X509CertificatePair = { "CertificatePair", "lib.org.bouncycastle.asn1.x509", ptrTable, methods, fields, 7, 0x1, 6, 2, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleAsn1X509CertificatePair;
}

@end

LibOrgBouncycastleAsn1X509CertificatePair *LibOrgBouncycastleAsn1X509CertificatePair_getInstanceWithId_(id obj) {
  LibOrgBouncycastleAsn1X509CertificatePair_initialize();
  if (obj == nil || [obj isKindOfClass:[LibOrgBouncycastleAsn1X509CertificatePair class]]) {
    return (LibOrgBouncycastleAsn1X509CertificatePair *) cast_chk(obj, [LibOrgBouncycastleAsn1X509CertificatePair class]);
  }
  if ([obj isKindOfClass:[LibOrgBouncycastleAsn1ASN1Sequence class]]) {
    return new_LibOrgBouncycastleAsn1X509CertificatePair_initWithLibOrgBouncycastleAsn1ASN1Sequence_((LibOrgBouncycastleAsn1ASN1Sequence *) obj);
  }
  @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$$", @"illegal object in getInstance: ", [[obj java_getClass] getName]));
}

void LibOrgBouncycastleAsn1X509CertificatePair_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1X509CertificatePair *self, LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  if ([((LibOrgBouncycastleAsn1ASN1Sequence *) nil_chk(seq)) size] != 1 && [seq size] != 2) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$I", @"Bad sequence size: ", [seq size]));
  }
  id<JavaUtilEnumeration> e = [seq getObjects];
  while ([((id<JavaUtilEnumeration>) nil_chk(e)) hasMoreElements]) {
    LibOrgBouncycastleAsn1ASN1TaggedObject *o = LibOrgBouncycastleAsn1ASN1TaggedObject_getInstanceWithId_([e nextElement]);
    if ([((LibOrgBouncycastleAsn1ASN1TaggedObject *) nil_chk(o)) getTagNo] == 0) {
      self->forward_ = LibOrgBouncycastleAsn1X509X509Certificate_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(o, true);
    }
    else if ([o getTagNo] == 1) {
      self->reverse_ = LibOrgBouncycastleAsn1X509X509Certificate_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(o, true);
    }
    else {
      @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$I", @"Bad tag number: ", [o getTagNo]));
    }
  }
}

LibOrgBouncycastleAsn1X509CertificatePair *new_LibOrgBouncycastleAsn1X509CertificatePair_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1X509CertificatePair, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

LibOrgBouncycastleAsn1X509CertificatePair *create_LibOrgBouncycastleAsn1X509CertificatePair_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1X509CertificatePair, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

void LibOrgBouncycastleAsn1X509CertificatePair_initWithLibOrgBouncycastleAsn1X509X509Certificate_withLibOrgBouncycastleAsn1X509X509Certificate_(LibOrgBouncycastleAsn1X509CertificatePair *self, LibOrgBouncycastleAsn1X509X509Certificate *forward, LibOrgBouncycastleAsn1X509X509Certificate *reverse) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->forward_ = forward;
  self->reverse_ = reverse;
}

LibOrgBouncycastleAsn1X509CertificatePair *new_LibOrgBouncycastleAsn1X509CertificatePair_initWithLibOrgBouncycastleAsn1X509X509Certificate_withLibOrgBouncycastleAsn1X509X509Certificate_(LibOrgBouncycastleAsn1X509X509Certificate *forward, LibOrgBouncycastleAsn1X509X509Certificate *reverse) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1X509CertificatePair, initWithLibOrgBouncycastleAsn1X509X509Certificate_withLibOrgBouncycastleAsn1X509X509Certificate_, forward, reverse)
}

LibOrgBouncycastleAsn1X509CertificatePair *create_LibOrgBouncycastleAsn1X509CertificatePair_initWithLibOrgBouncycastleAsn1X509X509Certificate_withLibOrgBouncycastleAsn1X509X509Certificate_(LibOrgBouncycastleAsn1X509X509Certificate *forward, LibOrgBouncycastleAsn1X509X509Certificate *reverse) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1X509CertificatePair, initWithLibOrgBouncycastleAsn1X509X509Certificate_withLibOrgBouncycastleAsn1X509X509Certificate_, forward, reverse)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleAsn1X509CertificatePair)
