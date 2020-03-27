//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/x509/ExtendedKeyUsage.java
//

#include "ASN1Encodable.h"
#include "ASN1EncodableVector.h"
#include "ASN1Object.h"
#include "ASN1ObjectIdentifier.h"
#include "ASN1Primitive.h"
#include "ASN1Sequence.h"
#include "ASN1TaggedObject.h"
#include "DERSequence.h"
#include "ExtendedKeyUsage.h"
#include "Extension.h"
#include "Extensions.h"
#include "IOSClass.h"
#include "IOSObjectArray.h"
#include "J2ObjC_source.h"
#include "KeyPurposeId.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/util/Enumeration.h"
#include "java/util/Hashtable.h"
#include "java/util/Vector.h"

@interface LibOrgBouncycastleAsn1X509ExtendedKeyUsage ()

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq;

@end

__attribute__((unused)) static void LibOrgBouncycastleAsn1X509ExtendedKeyUsage_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1X509ExtendedKeyUsage *self, LibOrgBouncycastleAsn1ASN1Sequence *seq);

__attribute__((unused)) static LibOrgBouncycastleAsn1X509ExtendedKeyUsage *new_LibOrgBouncycastleAsn1X509ExtendedKeyUsage_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleAsn1X509ExtendedKeyUsage *create_LibOrgBouncycastleAsn1X509ExtendedKeyUsage_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq);

@implementation LibOrgBouncycastleAsn1X509ExtendedKeyUsage

+ (LibOrgBouncycastleAsn1X509ExtendedKeyUsage *)getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject:(LibOrgBouncycastleAsn1ASN1TaggedObject *)obj
                                                                                          withBoolean:(jboolean)explicit_ {
  return LibOrgBouncycastleAsn1X509ExtendedKeyUsage_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(obj, explicit_);
}

+ (LibOrgBouncycastleAsn1X509ExtendedKeyUsage *)getInstanceWithId:(id)obj {
  return LibOrgBouncycastleAsn1X509ExtendedKeyUsage_getInstanceWithId_(obj);
}

+ (LibOrgBouncycastleAsn1X509ExtendedKeyUsage *)fromExtensionsWithLibOrgBouncycastleAsn1X509Extensions:(LibOrgBouncycastleAsn1X509Extensions *)extensions {
  return LibOrgBouncycastleAsn1X509ExtendedKeyUsage_fromExtensionsWithLibOrgBouncycastleAsn1X509Extensions_(extensions);
}

- (instancetype)initWithLibOrgBouncycastleAsn1X509KeyPurposeId:(LibOrgBouncycastleAsn1X509KeyPurposeId *)usage {
  LibOrgBouncycastleAsn1X509ExtendedKeyUsage_initWithLibOrgBouncycastleAsn1X509KeyPurposeId_(self, usage);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq {
  LibOrgBouncycastleAsn1X509ExtendedKeyUsage_initWithLibOrgBouncycastleAsn1ASN1Sequence_(self, seq);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleAsn1X509KeyPurposeIdArray:(IOSObjectArray *)usages {
  LibOrgBouncycastleAsn1X509ExtendedKeyUsage_initWithLibOrgBouncycastleAsn1X509KeyPurposeIdArray_(self, usages);
  return self;
}

- (instancetype)initWithJavaUtilVector:(JavaUtilVector *)usages {
  LibOrgBouncycastleAsn1X509ExtendedKeyUsage_initWithJavaUtilVector_(self, usages);
  return self;
}

- (jboolean)hasKeyPurposeIdWithLibOrgBouncycastleAsn1X509KeyPurposeId:(LibOrgBouncycastleAsn1X509KeyPurposeId *)keyPurposeId {
  return ([((JavaUtilHashtable *) nil_chk(usageTable_)) getWithId:keyPurposeId] != nil);
}

- (IOSObjectArray *)getUsages {
  IOSObjectArray *temp = [IOSObjectArray newArrayWithLength:[((LibOrgBouncycastleAsn1ASN1Sequence *) nil_chk(seq_)) size] type:LibOrgBouncycastleAsn1X509KeyPurposeId_class_()];
  jint i = 0;
  for (id<JavaUtilEnumeration> it = [((LibOrgBouncycastleAsn1ASN1Sequence *) nil_chk(seq_)) getObjects]; [((id<JavaUtilEnumeration>) nil_chk(it)) hasMoreElements]; ) {
    (void) IOSObjectArray_Set(temp, i++, LibOrgBouncycastleAsn1X509KeyPurposeId_getInstanceWithId_([it nextElement]));
  }
  return temp;
}

- (jint)size {
  return [((JavaUtilHashtable *) nil_chk(usageTable_)) size];
}

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive {
  return seq_;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, "LLibOrgBouncycastleAsn1X509ExtendedKeyUsage;", 0x9, 0, 1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1X509ExtendedKeyUsage;", 0x9, 0, 2, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1X509ExtendedKeyUsage;", 0x9, 3, 4, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 5, -1, -1, -1, -1 },
    { NULL, NULL, 0x2, -1, 6, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 7, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 8, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, 9, 5, -1, -1, -1, -1 },
    { NULL, "[LLibOrgBouncycastleAsn1X509KeyPurposeId;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject:withBoolean:);
  methods[1].selector = @selector(getInstanceWithId:);
  methods[2].selector = @selector(fromExtensionsWithLibOrgBouncycastleAsn1X509Extensions:);
  methods[3].selector = @selector(initWithLibOrgBouncycastleAsn1X509KeyPurposeId:);
  methods[4].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1Sequence:);
  methods[5].selector = @selector(initWithLibOrgBouncycastleAsn1X509KeyPurposeIdArray:);
  methods[6].selector = @selector(initWithJavaUtilVector:);
  methods[7].selector = @selector(hasKeyPurposeIdWithLibOrgBouncycastleAsn1X509KeyPurposeId:);
  methods[8].selector = @selector(getUsages);
  methods[9].selector = @selector(size);
  methods[10].selector = @selector(toASN1Primitive);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "usageTable_", "LJavaUtilHashtable;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "seq_", "LLibOrgBouncycastleAsn1ASN1Sequence;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "getInstance", "LLibOrgBouncycastleAsn1ASN1TaggedObject;Z", "LNSObject;", "fromExtensions", "LLibOrgBouncycastleAsn1X509Extensions;", "LLibOrgBouncycastleAsn1X509KeyPurposeId;", "LLibOrgBouncycastleAsn1ASN1Sequence;", "[LLibOrgBouncycastleAsn1X509KeyPurposeId;", "LJavaUtilVector;", "hasKeyPurposeId" };
  static const J2ObjcClassInfo _LibOrgBouncycastleAsn1X509ExtendedKeyUsage = { "ExtendedKeyUsage", "lib.org.bouncycastle.asn1.x509", ptrTable, methods, fields, 7, 0x1, 11, 2, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleAsn1X509ExtendedKeyUsage;
}

@end

LibOrgBouncycastleAsn1X509ExtendedKeyUsage *LibOrgBouncycastleAsn1X509ExtendedKeyUsage_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(LibOrgBouncycastleAsn1ASN1TaggedObject *obj, jboolean explicit_) {
  LibOrgBouncycastleAsn1X509ExtendedKeyUsage_initialize();
  return LibOrgBouncycastleAsn1X509ExtendedKeyUsage_getInstanceWithId_(LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(obj, explicit_));
}

LibOrgBouncycastleAsn1X509ExtendedKeyUsage *LibOrgBouncycastleAsn1X509ExtendedKeyUsage_getInstanceWithId_(id obj) {
  LibOrgBouncycastleAsn1X509ExtendedKeyUsage_initialize();
  if ([obj isKindOfClass:[LibOrgBouncycastleAsn1X509ExtendedKeyUsage class]]) {
    return (LibOrgBouncycastleAsn1X509ExtendedKeyUsage *) obj;
  }
  else if (obj != nil) {
    return new_LibOrgBouncycastleAsn1X509ExtendedKeyUsage_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithId_(obj));
  }
  return nil;
}

LibOrgBouncycastleAsn1X509ExtendedKeyUsage *LibOrgBouncycastleAsn1X509ExtendedKeyUsage_fromExtensionsWithLibOrgBouncycastleAsn1X509Extensions_(LibOrgBouncycastleAsn1X509Extensions *extensions) {
  LibOrgBouncycastleAsn1X509ExtendedKeyUsage_initialize();
  return LibOrgBouncycastleAsn1X509ExtendedKeyUsage_getInstanceWithId_([((LibOrgBouncycastleAsn1X509Extensions *) nil_chk(extensions)) getExtensionParsedValueWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:JreLoadStatic(LibOrgBouncycastleAsn1X509Extension, extendedKeyUsage)]);
}

void LibOrgBouncycastleAsn1X509ExtendedKeyUsage_initWithLibOrgBouncycastleAsn1X509KeyPurposeId_(LibOrgBouncycastleAsn1X509ExtendedKeyUsage *self, LibOrgBouncycastleAsn1X509KeyPurposeId *usage) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->usageTable_ = new_JavaUtilHashtable_init();
  self->seq_ = new_LibOrgBouncycastleAsn1DERSequence_initWithLibOrgBouncycastleAsn1ASN1Encodable_(usage);
  (void) [((JavaUtilHashtable *) nil_chk(self->usageTable_)) putWithId:usage withId:usage];
}

LibOrgBouncycastleAsn1X509ExtendedKeyUsage *new_LibOrgBouncycastleAsn1X509ExtendedKeyUsage_initWithLibOrgBouncycastleAsn1X509KeyPurposeId_(LibOrgBouncycastleAsn1X509KeyPurposeId *usage) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1X509ExtendedKeyUsage, initWithLibOrgBouncycastleAsn1X509KeyPurposeId_, usage)
}

LibOrgBouncycastleAsn1X509ExtendedKeyUsage *create_LibOrgBouncycastleAsn1X509ExtendedKeyUsage_initWithLibOrgBouncycastleAsn1X509KeyPurposeId_(LibOrgBouncycastleAsn1X509KeyPurposeId *usage) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1X509ExtendedKeyUsage, initWithLibOrgBouncycastleAsn1X509KeyPurposeId_, usage)
}

void LibOrgBouncycastleAsn1X509ExtendedKeyUsage_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1X509ExtendedKeyUsage *self, LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->usageTable_ = new_JavaUtilHashtable_init();
  self->seq_ = seq;
  id<JavaUtilEnumeration> e = [((LibOrgBouncycastleAsn1ASN1Sequence *) nil_chk(seq)) getObjects];
  while ([((id<JavaUtilEnumeration>) nil_chk(e)) hasMoreElements]) {
    id<LibOrgBouncycastleAsn1ASN1Encodable> o = (id<LibOrgBouncycastleAsn1ASN1Encodable>) cast_check([e nextElement], LibOrgBouncycastleAsn1ASN1Encodable_class_());
    if (!([[((id<LibOrgBouncycastleAsn1ASN1Encodable>) nil_chk(o)) toASN1Primitive] isKindOfClass:[LibOrgBouncycastleAsn1ASN1ObjectIdentifier class]])) {
      @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"Only ASN1ObjectIdentifiers allowed in ExtendedKeyUsage.");
    }
    (void) [((JavaUtilHashtable *) nil_chk(self->usageTable_)) putWithId:o withId:o];
  }
}

LibOrgBouncycastleAsn1X509ExtendedKeyUsage *new_LibOrgBouncycastleAsn1X509ExtendedKeyUsage_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1X509ExtendedKeyUsage, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

LibOrgBouncycastleAsn1X509ExtendedKeyUsage *create_LibOrgBouncycastleAsn1X509ExtendedKeyUsage_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1X509ExtendedKeyUsage, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

void LibOrgBouncycastleAsn1X509ExtendedKeyUsage_initWithLibOrgBouncycastleAsn1X509KeyPurposeIdArray_(LibOrgBouncycastleAsn1X509ExtendedKeyUsage *self, IOSObjectArray *usages) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->usageTable_ = new_JavaUtilHashtable_init();
  LibOrgBouncycastleAsn1ASN1EncodableVector *v = new_LibOrgBouncycastleAsn1ASN1EncodableVector_init();
  for (jint i = 0; i != ((IOSObjectArray *) nil_chk(usages))->size_; i++) {
    [v addWithLibOrgBouncycastleAsn1ASN1Encodable:IOSObjectArray_Get(usages, i)];
    (void) [((JavaUtilHashtable *) nil_chk(self->usageTable_)) putWithId:IOSObjectArray_Get(usages, i) withId:IOSObjectArray_Get(usages, i)];
  }
  self->seq_ = new_LibOrgBouncycastleAsn1DERSequence_initWithLibOrgBouncycastleAsn1ASN1EncodableVector_(v);
}

LibOrgBouncycastleAsn1X509ExtendedKeyUsage *new_LibOrgBouncycastleAsn1X509ExtendedKeyUsage_initWithLibOrgBouncycastleAsn1X509KeyPurposeIdArray_(IOSObjectArray *usages) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1X509ExtendedKeyUsage, initWithLibOrgBouncycastleAsn1X509KeyPurposeIdArray_, usages)
}

LibOrgBouncycastleAsn1X509ExtendedKeyUsage *create_LibOrgBouncycastleAsn1X509ExtendedKeyUsage_initWithLibOrgBouncycastleAsn1X509KeyPurposeIdArray_(IOSObjectArray *usages) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1X509ExtendedKeyUsage, initWithLibOrgBouncycastleAsn1X509KeyPurposeIdArray_, usages)
}

void LibOrgBouncycastleAsn1X509ExtendedKeyUsage_initWithJavaUtilVector_(LibOrgBouncycastleAsn1X509ExtendedKeyUsage *self, JavaUtilVector *usages) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->usageTable_ = new_JavaUtilHashtable_init();
  LibOrgBouncycastleAsn1ASN1EncodableVector *v = new_LibOrgBouncycastleAsn1ASN1EncodableVector_init();
  id<JavaUtilEnumeration> e = [((JavaUtilVector *) nil_chk(usages)) elements];
  while ([((id<JavaUtilEnumeration>) nil_chk(e)) hasMoreElements]) {
    LibOrgBouncycastleAsn1X509KeyPurposeId *o = LibOrgBouncycastleAsn1X509KeyPurposeId_getInstanceWithId_([e nextElement]);
    [v addWithLibOrgBouncycastleAsn1ASN1Encodable:o];
    (void) [((JavaUtilHashtable *) nil_chk(self->usageTable_)) putWithId:o withId:o];
  }
  self->seq_ = new_LibOrgBouncycastleAsn1DERSequence_initWithLibOrgBouncycastleAsn1ASN1EncodableVector_(v);
}

LibOrgBouncycastleAsn1X509ExtendedKeyUsage *new_LibOrgBouncycastleAsn1X509ExtendedKeyUsage_initWithJavaUtilVector_(JavaUtilVector *usages) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1X509ExtendedKeyUsage, initWithJavaUtilVector_, usages)
}

LibOrgBouncycastleAsn1X509ExtendedKeyUsage *create_LibOrgBouncycastleAsn1X509ExtendedKeyUsage_initWithJavaUtilVector_(JavaUtilVector *usages) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1X509ExtendedKeyUsage, initWithJavaUtilVector_, usages)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleAsn1X509ExtendedKeyUsage)
