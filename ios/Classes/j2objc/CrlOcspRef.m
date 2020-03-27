//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/esf/CrlOcspRef.java
//

#include "ASN1EncodableVector.h"
#include "ASN1Object.h"
#include "ASN1Primitive.h"
#include "ASN1Sequence.h"
#include "ASN1TaggedObject.h"
#include "CrlListID.h"
#include "CrlOcspRef.h"
#include "DERSequence.h"
#include "DERTaggedObject.h"
#include "J2ObjC_source.h"
#include "OcspListID.h"
#include "OtherRevRefs.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/util/Enumeration.h"

@interface LibOrgBouncycastleAsn1EsfCrlOcspRef () {
 @public
  LibOrgBouncycastleAsn1EsfCrlListID *crlids_;
  LibOrgBouncycastleAsn1EsfOcspListID *ocspids_;
  LibOrgBouncycastleAsn1EsfOtherRevRefs *otherRev_;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1EsfCrlOcspRef, crlids_, LibOrgBouncycastleAsn1EsfCrlListID *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1EsfCrlOcspRef, ocspids_, LibOrgBouncycastleAsn1EsfOcspListID *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1EsfCrlOcspRef, otherRev_, LibOrgBouncycastleAsn1EsfOtherRevRefs *)

__attribute__((unused)) static void LibOrgBouncycastleAsn1EsfCrlOcspRef_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1EsfCrlOcspRef *self, LibOrgBouncycastleAsn1ASN1Sequence *seq);

__attribute__((unused)) static LibOrgBouncycastleAsn1EsfCrlOcspRef *new_LibOrgBouncycastleAsn1EsfCrlOcspRef_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleAsn1EsfCrlOcspRef *create_LibOrgBouncycastleAsn1EsfCrlOcspRef_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq);

@implementation LibOrgBouncycastleAsn1EsfCrlOcspRef

+ (LibOrgBouncycastleAsn1EsfCrlOcspRef *)getInstanceWithId:(id)obj {
  return LibOrgBouncycastleAsn1EsfCrlOcspRef_getInstanceWithId_(obj);
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq {
  LibOrgBouncycastleAsn1EsfCrlOcspRef_initWithLibOrgBouncycastleAsn1ASN1Sequence_(self, seq);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleAsn1EsfCrlListID:(LibOrgBouncycastleAsn1EsfCrlListID *)crlids
                   withLibOrgBouncycastleAsn1EsfOcspListID:(LibOrgBouncycastleAsn1EsfOcspListID *)ocspids
                 withLibOrgBouncycastleAsn1EsfOtherRevRefs:(LibOrgBouncycastleAsn1EsfOtherRevRefs *)otherRev {
  LibOrgBouncycastleAsn1EsfCrlOcspRef_initWithLibOrgBouncycastleAsn1EsfCrlListID_withLibOrgBouncycastleAsn1EsfOcspListID_withLibOrgBouncycastleAsn1EsfOtherRevRefs_(self, crlids, ocspids, otherRev);
  return self;
}

- (LibOrgBouncycastleAsn1EsfCrlListID *)getCrlids {
  return self->crlids_;
}

- (LibOrgBouncycastleAsn1EsfOcspListID *)getOcspids {
  return self->ocspids_;
}

- (LibOrgBouncycastleAsn1EsfOtherRevRefs *)getOtherRev {
  return self->otherRev_;
}

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive {
  LibOrgBouncycastleAsn1ASN1EncodableVector *v = new_LibOrgBouncycastleAsn1ASN1EncodableVector_init();
  if (nil != self->crlids_) {
    [v addWithLibOrgBouncycastleAsn1ASN1Encodable:new_LibOrgBouncycastleAsn1DERTaggedObject_initWithBoolean_withInt_withLibOrgBouncycastleAsn1ASN1Encodable_(true, 0, [self->crlids_ toASN1Primitive])];
  }
  if (nil != self->ocspids_) {
    [v addWithLibOrgBouncycastleAsn1ASN1Encodable:new_LibOrgBouncycastleAsn1DERTaggedObject_initWithBoolean_withInt_withLibOrgBouncycastleAsn1ASN1Encodable_(true, 1, [self->ocspids_ toASN1Primitive])];
  }
  if (nil != self->otherRev_) {
    [v addWithLibOrgBouncycastleAsn1ASN1Encodable:new_LibOrgBouncycastleAsn1DERTaggedObject_initWithBoolean_withInt_withLibOrgBouncycastleAsn1ASN1Encodable_(true, 2, [self->otherRev_ toASN1Primitive])];
  }
  return new_LibOrgBouncycastleAsn1DERSequence_initWithLibOrgBouncycastleAsn1ASN1EncodableVector_(v);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, "LLibOrgBouncycastleAsn1EsfCrlOcspRef;", 0x9, 0, 1, -1, -1, -1, -1 },
    { NULL, NULL, 0x2, -1, 2, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 3, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1EsfCrlListID;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1EsfOcspListID;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1EsfOtherRevRefs;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(getInstanceWithId:);
  methods[1].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1Sequence:);
  methods[2].selector = @selector(initWithLibOrgBouncycastleAsn1EsfCrlListID:withLibOrgBouncycastleAsn1EsfOcspListID:withLibOrgBouncycastleAsn1EsfOtherRevRefs:);
  methods[3].selector = @selector(getCrlids);
  methods[4].selector = @selector(getOcspids);
  methods[5].selector = @selector(getOtherRev);
  methods[6].selector = @selector(toASN1Primitive);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "crlids_", "LLibOrgBouncycastleAsn1EsfCrlListID;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "ocspids_", "LLibOrgBouncycastleAsn1EsfOcspListID;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "otherRev_", "LLibOrgBouncycastleAsn1EsfOtherRevRefs;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "getInstance", "LNSObject;", "LLibOrgBouncycastleAsn1ASN1Sequence;", "LLibOrgBouncycastleAsn1EsfCrlListID;LLibOrgBouncycastleAsn1EsfOcspListID;LLibOrgBouncycastleAsn1EsfOtherRevRefs;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleAsn1EsfCrlOcspRef = { "CrlOcspRef", "lib.org.bouncycastle.asn1.esf", ptrTable, methods, fields, 7, 0x1, 7, 3, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleAsn1EsfCrlOcspRef;
}

@end

LibOrgBouncycastleAsn1EsfCrlOcspRef *LibOrgBouncycastleAsn1EsfCrlOcspRef_getInstanceWithId_(id obj) {
  LibOrgBouncycastleAsn1EsfCrlOcspRef_initialize();
  if ([obj isKindOfClass:[LibOrgBouncycastleAsn1EsfCrlOcspRef class]]) {
    return (LibOrgBouncycastleAsn1EsfCrlOcspRef *) obj;
  }
  else if (obj != nil) {
    return new_LibOrgBouncycastleAsn1EsfCrlOcspRef_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithId_(obj));
  }
  return nil;
}

void LibOrgBouncycastleAsn1EsfCrlOcspRef_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1EsfCrlOcspRef *self, LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  id<JavaUtilEnumeration> e = [((LibOrgBouncycastleAsn1ASN1Sequence *) nil_chk(seq)) getObjects];
  while ([((id<JavaUtilEnumeration>) nil_chk(e)) hasMoreElements]) {
    LibOrgBouncycastleAsn1ASN1TaggedObject *o = (LibOrgBouncycastleAsn1ASN1TaggedObject *) cast_chk([e nextElement], [LibOrgBouncycastleAsn1ASN1TaggedObject class]);
    switch ([((LibOrgBouncycastleAsn1ASN1TaggedObject *) nil_chk(o)) getTagNo]) {
      case 0:
      self->crlids_ = LibOrgBouncycastleAsn1EsfCrlListID_getInstanceWithId_([o getObject]);
      break;
      case 1:
      self->ocspids_ = LibOrgBouncycastleAsn1EsfOcspListID_getInstanceWithId_([o getObject]);
      break;
      case 2:
      self->otherRev_ = LibOrgBouncycastleAsn1EsfOtherRevRefs_getInstanceWithId_([o getObject]);
      break;
      default:
      @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"illegal tag");
    }
  }
}

LibOrgBouncycastleAsn1EsfCrlOcspRef *new_LibOrgBouncycastleAsn1EsfCrlOcspRef_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1EsfCrlOcspRef, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

LibOrgBouncycastleAsn1EsfCrlOcspRef *create_LibOrgBouncycastleAsn1EsfCrlOcspRef_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1EsfCrlOcspRef, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

void LibOrgBouncycastleAsn1EsfCrlOcspRef_initWithLibOrgBouncycastleAsn1EsfCrlListID_withLibOrgBouncycastleAsn1EsfOcspListID_withLibOrgBouncycastleAsn1EsfOtherRevRefs_(LibOrgBouncycastleAsn1EsfCrlOcspRef *self, LibOrgBouncycastleAsn1EsfCrlListID *crlids, LibOrgBouncycastleAsn1EsfOcspListID *ocspids, LibOrgBouncycastleAsn1EsfOtherRevRefs *otherRev) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->crlids_ = crlids;
  self->ocspids_ = ocspids;
  self->otherRev_ = otherRev;
}

LibOrgBouncycastleAsn1EsfCrlOcspRef *new_LibOrgBouncycastleAsn1EsfCrlOcspRef_initWithLibOrgBouncycastleAsn1EsfCrlListID_withLibOrgBouncycastleAsn1EsfOcspListID_withLibOrgBouncycastleAsn1EsfOtherRevRefs_(LibOrgBouncycastleAsn1EsfCrlListID *crlids, LibOrgBouncycastleAsn1EsfOcspListID *ocspids, LibOrgBouncycastleAsn1EsfOtherRevRefs *otherRev) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1EsfCrlOcspRef, initWithLibOrgBouncycastleAsn1EsfCrlListID_withLibOrgBouncycastleAsn1EsfOcspListID_withLibOrgBouncycastleAsn1EsfOtherRevRefs_, crlids, ocspids, otherRev)
}

LibOrgBouncycastleAsn1EsfCrlOcspRef *create_LibOrgBouncycastleAsn1EsfCrlOcspRef_initWithLibOrgBouncycastleAsn1EsfCrlListID_withLibOrgBouncycastleAsn1EsfOcspListID_withLibOrgBouncycastleAsn1EsfOtherRevRefs_(LibOrgBouncycastleAsn1EsfCrlListID *crlids, LibOrgBouncycastleAsn1EsfOcspListID *ocspids, LibOrgBouncycastleAsn1EsfOtherRevRefs *otherRev) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1EsfCrlOcspRef, initWithLibOrgBouncycastleAsn1EsfCrlListID_withLibOrgBouncycastleAsn1EsfOcspListID_withLibOrgBouncycastleAsn1EsfOtherRevRefs_, crlids, ocspids, otherRev)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleAsn1EsfCrlOcspRef)
