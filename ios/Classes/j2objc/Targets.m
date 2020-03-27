//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/x509/Targets.java
//

#include "ASN1Object.h"
#include "ASN1Primitive.h"
#include "ASN1Sequence.h"
#include "DERSequence.h"
#include "IOSClass.h"
#include "IOSObjectArray.h"
#include "J2ObjC_source.h"
#include "Target.h"
#include "Targets.h"
#include "java/util/Enumeration.h"

@interface LibOrgBouncycastleAsn1X509Targets () {
 @public
  LibOrgBouncycastleAsn1ASN1Sequence *targets_;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)targets;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1X509Targets, targets_, LibOrgBouncycastleAsn1ASN1Sequence *)

__attribute__((unused)) static void LibOrgBouncycastleAsn1X509Targets_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1X509Targets *self, LibOrgBouncycastleAsn1ASN1Sequence *targets);

__attribute__((unused)) static LibOrgBouncycastleAsn1X509Targets *new_LibOrgBouncycastleAsn1X509Targets_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *targets) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleAsn1X509Targets *create_LibOrgBouncycastleAsn1X509Targets_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *targets);

@implementation LibOrgBouncycastleAsn1X509Targets

+ (LibOrgBouncycastleAsn1X509Targets *)getInstanceWithId:(id)obj {
  return LibOrgBouncycastleAsn1X509Targets_getInstanceWithId_(obj);
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)targets {
  LibOrgBouncycastleAsn1X509Targets_initWithLibOrgBouncycastleAsn1ASN1Sequence_(self, targets);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleAsn1X509TargetArray:(IOSObjectArray *)targets {
  LibOrgBouncycastleAsn1X509Targets_initWithLibOrgBouncycastleAsn1X509TargetArray_(self, targets);
  return self;
}

- (IOSObjectArray *)getTargets {
  IOSObjectArray *targs = [IOSObjectArray newArrayWithLength:[((LibOrgBouncycastleAsn1ASN1Sequence *) nil_chk(targets_)) size] type:LibOrgBouncycastleAsn1X509Target_class_()];
  jint count = 0;
  for (id<JavaUtilEnumeration> e = [((LibOrgBouncycastleAsn1ASN1Sequence *) nil_chk(targets_)) getObjects]; [((id<JavaUtilEnumeration>) nil_chk(e)) hasMoreElements]; ) {
    (void) IOSObjectArray_Set(targs, count++, LibOrgBouncycastleAsn1X509Target_getInstanceWithId_([e nextElement]));
  }
  return targs;
}

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive {
  return targets_;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, "LLibOrgBouncycastleAsn1X509Targets;", 0x9, 0, 1, -1, -1, -1, -1 },
    { NULL, NULL, 0x2, -1, 2, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 3, -1, -1, -1, -1 },
    { NULL, "[LLibOrgBouncycastleAsn1X509Target;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(getInstanceWithId:);
  methods[1].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1Sequence:);
  methods[2].selector = @selector(initWithLibOrgBouncycastleAsn1X509TargetArray:);
  methods[3].selector = @selector(getTargets);
  methods[4].selector = @selector(toASN1Primitive);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "targets_", "LLibOrgBouncycastleAsn1ASN1Sequence;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "getInstance", "LNSObject;", "LLibOrgBouncycastleAsn1ASN1Sequence;", "[LLibOrgBouncycastleAsn1X509Target;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleAsn1X509Targets = { "Targets", "lib.org.bouncycastle.asn1.x509", ptrTable, methods, fields, 7, 0x1, 5, 1, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleAsn1X509Targets;
}

@end

LibOrgBouncycastleAsn1X509Targets *LibOrgBouncycastleAsn1X509Targets_getInstanceWithId_(id obj) {
  LibOrgBouncycastleAsn1X509Targets_initialize();
  if ([obj isKindOfClass:[LibOrgBouncycastleAsn1X509Targets class]]) {
    return (LibOrgBouncycastleAsn1X509Targets *) obj;
  }
  else if (obj != nil) {
    return new_LibOrgBouncycastleAsn1X509Targets_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithId_(obj));
  }
  return nil;
}

void LibOrgBouncycastleAsn1X509Targets_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1X509Targets *self, LibOrgBouncycastleAsn1ASN1Sequence *targets) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->targets_ = targets;
}

LibOrgBouncycastleAsn1X509Targets *new_LibOrgBouncycastleAsn1X509Targets_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *targets) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1X509Targets, initWithLibOrgBouncycastleAsn1ASN1Sequence_, targets)
}

LibOrgBouncycastleAsn1X509Targets *create_LibOrgBouncycastleAsn1X509Targets_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *targets) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1X509Targets, initWithLibOrgBouncycastleAsn1ASN1Sequence_, targets)
}

void LibOrgBouncycastleAsn1X509Targets_initWithLibOrgBouncycastleAsn1X509TargetArray_(LibOrgBouncycastleAsn1X509Targets *self, IOSObjectArray *targets) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->targets_ = new_LibOrgBouncycastleAsn1DERSequence_initWithLibOrgBouncycastleAsn1ASN1EncodableArray_(targets);
}

LibOrgBouncycastleAsn1X509Targets *new_LibOrgBouncycastleAsn1X509Targets_initWithLibOrgBouncycastleAsn1X509TargetArray_(IOSObjectArray *targets) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1X509Targets, initWithLibOrgBouncycastleAsn1X509TargetArray_, targets)
}

LibOrgBouncycastleAsn1X509Targets *create_LibOrgBouncycastleAsn1X509Targets_initWithLibOrgBouncycastleAsn1X509TargetArray_(IOSObjectArray *targets) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1X509Targets, initWithLibOrgBouncycastleAsn1X509TargetArray_, targets)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleAsn1X509Targets)
