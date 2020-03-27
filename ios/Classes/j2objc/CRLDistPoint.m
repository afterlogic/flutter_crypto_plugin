//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/x509/CRLDistPoint.java
//

#include "ASN1Encodable.h"
#include "ASN1EncodableVector.h"
#include "ASN1Object.h"
#include "ASN1ObjectIdentifier.h"
#include "ASN1Primitive.h"
#include "ASN1Sequence.h"
#include "ASN1TaggedObject.h"
#include "CRLDistPoint.h"
#include "DERSequence.h"
#include "DistributionPoint.h"
#include "Extension.h"
#include "Extensions.h"
#include "IOSClass.h"
#include "IOSObjectArray.h"
#include "J2ObjC_source.h"
#include "Strings.h"
#include "java/lang/StringBuffer.h"

@interface LibOrgBouncycastleAsn1X509CRLDistPoint ()

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq;

@end

__attribute__((unused)) static void LibOrgBouncycastleAsn1X509CRLDistPoint_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1X509CRLDistPoint *self, LibOrgBouncycastleAsn1ASN1Sequence *seq);

__attribute__((unused)) static LibOrgBouncycastleAsn1X509CRLDistPoint *new_LibOrgBouncycastleAsn1X509CRLDistPoint_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleAsn1X509CRLDistPoint *create_LibOrgBouncycastleAsn1X509CRLDistPoint_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq);

@implementation LibOrgBouncycastleAsn1X509CRLDistPoint

+ (LibOrgBouncycastleAsn1X509CRLDistPoint *)getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject:(LibOrgBouncycastleAsn1ASN1TaggedObject *)obj
                                                                                      withBoolean:(jboolean)explicit_ {
  return LibOrgBouncycastleAsn1X509CRLDistPoint_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(obj, explicit_);
}

+ (LibOrgBouncycastleAsn1X509CRLDistPoint *)fromExtensionsWithLibOrgBouncycastleAsn1X509Extensions:(LibOrgBouncycastleAsn1X509Extensions *)extensions {
  return LibOrgBouncycastleAsn1X509CRLDistPoint_fromExtensionsWithLibOrgBouncycastleAsn1X509Extensions_(extensions);
}

+ (LibOrgBouncycastleAsn1X509CRLDistPoint *)getInstanceWithId:(id)obj {
  return LibOrgBouncycastleAsn1X509CRLDistPoint_getInstanceWithId_(obj);
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq {
  LibOrgBouncycastleAsn1X509CRLDistPoint_initWithLibOrgBouncycastleAsn1ASN1Sequence_(self, seq);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleAsn1X509DistributionPointArray:(IOSObjectArray *)points {
  LibOrgBouncycastleAsn1X509CRLDistPoint_initWithLibOrgBouncycastleAsn1X509DistributionPointArray_(self, points);
  return self;
}

- (IOSObjectArray *)getDistributionPoints {
  IOSObjectArray *dp = [IOSObjectArray newArrayWithLength:[((LibOrgBouncycastleAsn1ASN1Sequence *) nil_chk(seq_)) size] type:LibOrgBouncycastleAsn1X509DistributionPoint_class_()];
  for (jint i = 0; i != [((LibOrgBouncycastleAsn1ASN1Sequence *) nil_chk(seq_)) size]; i++) {
    (void) IOSObjectArray_Set(dp, i, LibOrgBouncycastleAsn1X509DistributionPoint_getInstanceWithId_([((LibOrgBouncycastleAsn1ASN1Sequence *) nil_chk(seq_)) getObjectAtWithInt:i]));
  }
  return dp;
}

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive {
  return seq_;
}

- (NSString *)description {
  JavaLangStringBuffer *buf = new_JavaLangStringBuffer_init();
  NSString *sep = LibOrgBouncycastleUtilStrings_lineSeparator();
  (void) [buf appendWithNSString:@"CRLDistPoint:"];
  (void) [buf appendWithNSString:sep];
  IOSObjectArray *dp = [self getDistributionPoints];
  for (jint i = 0; i != ((IOSObjectArray *) nil_chk(dp))->size_; i++) {
    (void) [buf appendWithNSString:@"    "];
    (void) [buf appendWithId:IOSObjectArray_Get(dp, i)];
    (void) [buf appendWithNSString:sep];
  }
  return [buf description];
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, "LLibOrgBouncycastleAsn1X509CRLDistPoint;", 0x9, 0, 1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1X509CRLDistPoint;", 0x9, 2, 3, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1X509CRLDistPoint;", 0x9, 0, 4, -1, -1, -1, -1 },
    { NULL, NULL, 0x2, -1, 5, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 6, -1, -1, -1, -1 },
    { NULL, "[LLibOrgBouncycastleAsn1X509DistributionPoint;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x1, 7, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject:withBoolean:);
  methods[1].selector = @selector(fromExtensionsWithLibOrgBouncycastleAsn1X509Extensions:);
  methods[2].selector = @selector(getInstanceWithId:);
  methods[3].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1Sequence:);
  methods[4].selector = @selector(initWithLibOrgBouncycastleAsn1X509DistributionPointArray:);
  methods[5].selector = @selector(getDistributionPoints);
  methods[6].selector = @selector(toASN1Primitive);
  methods[7].selector = @selector(description);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "seq_", "LLibOrgBouncycastleAsn1ASN1Sequence;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "getInstance", "LLibOrgBouncycastleAsn1ASN1TaggedObject;Z", "fromExtensions", "LLibOrgBouncycastleAsn1X509Extensions;", "LNSObject;", "LLibOrgBouncycastleAsn1ASN1Sequence;", "[LLibOrgBouncycastleAsn1X509DistributionPoint;", "toString" };
  static const J2ObjcClassInfo _LibOrgBouncycastleAsn1X509CRLDistPoint = { "CRLDistPoint", "lib.org.bouncycastle.asn1.x509", ptrTable, methods, fields, 7, 0x1, 8, 1, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleAsn1X509CRLDistPoint;
}

@end

LibOrgBouncycastleAsn1X509CRLDistPoint *LibOrgBouncycastleAsn1X509CRLDistPoint_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(LibOrgBouncycastleAsn1ASN1TaggedObject *obj, jboolean explicit_) {
  LibOrgBouncycastleAsn1X509CRLDistPoint_initialize();
  return LibOrgBouncycastleAsn1X509CRLDistPoint_getInstanceWithId_(LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(obj, explicit_));
}

LibOrgBouncycastleAsn1X509CRLDistPoint *LibOrgBouncycastleAsn1X509CRLDistPoint_fromExtensionsWithLibOrgBouncycastleAsn1X509Extensions_(LibOrgBouncycastleAsn1X509Extensions *extensions) {
  LibOrgBouncycastleAsn1X509CRLDistPoint_initialize();
  return LibOrgBouncycastleAsn1X509CRLDistPoint_getInstanceWithId_([((LibOrgBouncycastleAsn1X509Extensions *) nil_chk(extensions)) getExtensionParsedValueWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:JreLoadStatic(LibOrgBouncycastleAsn1X509Extension, cRLDistributionPoints)]);
}

LibOrgBouncycastleAsn1X509CRLDistPoint *LibOrgBouncycastleAsn1X509CRLDistPoint_getInstanceWithId_(id obj) {
  LibOrgBouncycastleAsn1X509CRLDistPoint_initialize();
  if ([obj isKindOfClass:[LibOrgBouncycastleAsn1X509CRLDistPoint class]]) {
    return (LibOrgBouncycastleAsn1X509CRLDistPoint *) obj;
  }
  else if (obj != nil) {
    return new_LibOrgBouncycastleAsn1X509CRLDistPoint_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithId_(obj));
  }
  return nil;
}

void LibOrgBouncycastleAsn1X509CRLDistPoint_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1X509CRLDistPoint *self, LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->seq_ = nil;
  self->seq_ = seq;
}

LibOrgBouncycastleAsn1X509CRLDistPoint *new_LibOrgBouncycastleAsn1X509CRLDistPoint_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1X509CRLDistPoint, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

LibOrgBouncycastleAsn1X509CRLDistPoint *create_LibOrgBouncycastleAsn1X509CRLDistPoint_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1X509CRLDistPoint, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

void LibOrgBouncycastleAsn1X509CRLDistPoint_initWithLibOrgBouncycastleAsn1X509DistributionPointArray_(LibOrgBouncycastleAsn1X509CRLDistPoint *self, IOSObjectArray *points) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->seq_ = nil;
  LibOrgBouncycastleAsn1ASN1EncodableVector *v = new_LibOrgBouncycastleAsn1ASN1EncodableVector_init();
  for (jint i = 0; i != ((IOSObjectArray *) nil_chk(points))->size_; i++) {
    [v addWithLibOrgBouncycastleAsn1ASN1Encodable:IOSObjectArray_Get(points, i)];
  }
  self->seq_ = new_LibOrgBouncycastleAsn1DERSequence_initWithLibOrgBouncycastleAsn1ASN1EncodableVector_(v);
}

LibOrgBouncycastleAsn1X509CRLDistPoint *new_LibOrgBouncycastleAsn1X509CRLDistPoint_initWithLibOrgBouncycastleAsn1X509DistributionPointArray_(IOSObjectArray *points) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1X509CRLDistPoint, initWithLibOrgBouncycastleAsn1X509DistributionPointArray_, points)
}

LibOrgBouncycastleAsn1X509CRLDistPoint *create_LibOrgBouncycastleAsn1X509CRLDistPoint_initWithLibOrgBouncycastleAsn1X509DistributionPointArray_(IOSObjectArray *points) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1X509CRLDistPoint, initWithLibOrgBouncycastleAsn1X509DistributionPointArray_, points)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleAsn1X509CRLDistPoint)