//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/x509/Extensions.java
//

#include "ASN1Encodable.h"
#include "ASN1EncodableVector.h"
#include "ASN1Object.h"
#include "ASN1ObjectIdentifier.h"
#include "ASN1Primitive.h"
#include "ASN1Sequence.h"
#include "ASN1TaggedObject.h"
#include "DERSequence.h"
#include "Extension.h"
#include "Extensions.h"
#include "IOSClass.h"
#include "IOSObjectArray.h"
#include "J2ObjC_source.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/util/Enumeration.h"
#include "java/util/Hashtable.h"
#include "java/util/Vector.h"

@interface LibOrgBouncycastleAsn1X509Extensions () {
 @public
  JavaUtilHashtable *extensions_;
  JavaUtilVector *ordering_;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq;

- (IOSObjectArray *)getExtensionOIDsWithBoolean:(jboolean)isCritical;

- (IOSObjectArray *)toOidArrayWithJavaUtilVector:(JavaUtilVector *)oidVec;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1X509Extensions, extensions_, JavaUtilHashtable *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1X509Extensions, ordering_, JavaUtilVector *)

__attribute__((unused)) static void LibOrgBouncycastleAsn1X509Extensions_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1X509Extensions *self, LibOrgBouncycastleAsn1ASN1Sequence *seq);

__attribute__((unused)) static LibOrgBouncycastleAsn1X509Extensions *new_LibOrgBouncycastleAsn1X509Extensions_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleAsn1X509Extensions *create_LibOrgBouncycastleAsn1X509Extensions_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq);

__attribute__((unused)) static IOSObjectArray *LibOrgBouncycastleAsn1X509Extensions_getExtensionOIDsWithBoolean_(LibOrgBouncycastleAsn1X509Extensions *self, jboolean isCritical);

__attribute__((unused)) static IOSObjectArray *LibOrgBouncycastleAsn1X509Extensions_toOidArrayWithJavaUtilVector_(LibOrgBouncycastleAsn1X509Extensions *self, JavaUtilVector *oidVec);

@implementation LibOrgBouncycastleAsn1X509Extensions

+ (LibOrgBouncycastleAsn1X509Extensions *)getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject:(LibOrgBouncycastleAsn1ASN1TaggedObject *)obj
                                                                                    withBoolean:(jboolean)explicit_ {
  return LibOrgBouncycastleAsn1X509Extensions_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(obj, explicit_);
}

+ (LibOrgBouncycastleAsn1X509Extensions *)getInstanceWithId:(id)obj {
  return LibOrgBouncycastleAsn1X509Extensions_getInstanceWithId_(obj);
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq {
  LibOrgBouncycastleAsn1X509Extensions_initWithLibOrgBouncycastleAsn1ASN1Sequence_(self, seq);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleAsn1X509Extension:(LibOrgBouncycastleAsn1X509Extension *)extension {
  LibOrgBouncycastleAsn1X509Extensions_initWithLibOrgBouncycastleAsn1X509Extension_(self, extension);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleAsn1X509ExtensionArray:(IOSObjectArray *)extensions {
  LibOrgBouncycastleAsn1X509Extensions_initWithLibOrgBouncycastleAsn1X509ExtensionArray_(self, extensions);
  return self;
}

- (id<JavaUtilEnumeration>)oids {
  return [((JavaUtilVector *) nil_chk(ordering_)) elements];
}

- (LibOrgBouncycastleAsn1X509Extension *)getExtensionWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)oid {
  return (LibOrgBouncycastleAsn1X509Extension *) cast_chk([((JavaUtilHashtable *) nil_chk(extensions_)) getWithId:oid], [LibOrgBouncycastleAsn1X509Extension class]);
}

- (id<LibOrgBouncycastleAsn1ASN1Encodable>)getExtensionParsedValueWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)oid {
  LibOrgBouncycastleAsn1X509Extension *ext = [self getExtensionWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:oid];
  if (ext != nil) {
    return [ext getParsedValue];
  }
  return nil;
}

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive {
  LibOrgBouncycastleAsn1ASN1EncodableVector *vec = new_LibOrgBouncycastleAsn1ASN1EncodableVector_init();
  id<JavaUtilEnumeration> e = [((JavaUtilVector *) nil_chk(ordering_)) elements];
  while ([((id<JavaUtilEnumeration>) nil_chk(e)) hasMoreElements]) {
    LibOrgBouncycastleAsn1ASN1ObjectIdentifier *oid = (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *) cast_chk([e nextElement], [LibOrgBouncycastleAsn1ASN1ObjectIdentifier class]);
    LibOrgBouncycastleAsn1X509Extension *ext = (LibOrgBouncycastleAsn1X509Extension *) cast_chk([((JavaUtilHashtable *) nil_chk(extensions_)) getWithId:oid], [LibOrgBouncycastleAsn1X509Extension class]);
    [vec addWithLibOrgBouncycastleAsn1ASN1Encodable:ext];
  }
  return new_LibOrgBouncycastleAsn1DERSequence_initWithLibOrgBouncycastleAsn1ASN1EncodableVector_(vec);
}

- (jboolean)equivalentWithLibOrgBouncycastleAsn1X509Extensions:(LibOrgBouncycastleAsn1X509Extensions *)other {
  if ([((JavaUtilHashtable *) nil_chk(extensions_)) size] != [((JavaUtilHashtable *) nil_chk(((LibOrgBouncycastleAsn1X509Extensions *) nil_chk(other))->extensions_)) size]) {
    return false;
  }
  id<JavaUtilEnumeration> e1 = [((JavaUtilHashtable *) nil_chk(extensions_)) keys];
  while ([((id<JavaUtilEnumeration>) nil_chk(e1)) hasMoreElements]) {
    id key = [e1 nextElement];
    if (![nil_chk([((JavaUtilHashtable *) nil_chk(extensions_)) getWithId:key]) isEqual:[((JavaUtilHashtable *) nil_chk(other->extensions_)) getWithId:key]]) {
      return false;
    }
  }
  return true;
}

- (IOSObjectArray *)getExtensionOIDs {
  return LibOrgBouncycastleAsn1X509Extensions_toOidArrayWithJavaUtilVector_(self, ordering_);
}

- (IOSObjectArray *)getNonCriticalExtensionOIDs {
  return LibOrgBouncycastleAsn1X509Extensions_getExtensionOIDsWithBoolean_(self, false);
}

- (IOSObjectArray *)getCriticalExtensionOIDs {
  return LibOrgBouncycastleAsn1X509Extensions_getExtensionOIDsWithBoolean_(self, true);
}

- (IOSObjectArray *)getExtensionOIDsWithBoolean:(jboolean)isCritical {
  return LibOrgBouncycastleAsn1X509Extensions_getExtensionOIDsWithBoolean_(self, isCritical);
}

- (IOSObjectArray *)toOidArrayWithJavaUtilVector:(JavaUtilVector *)oidVec {
  return LibOrgBouncycastleAsn1X509Extensions_toOidArrayWithJavaUtilVector_(self, oidVec);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, "LLibOrgBouncycastleAsn1X509Extensions;", 0x9, 0, 1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1X509Extensions;", 0x9, 0, 2, -1, -1, -1, -1 },
    { NULL, NULL, 0x2, -1, 3, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 4, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 5, -1, -1, -1, -1 },
    { NULL, "LJavaUtilEnumeration;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1X509Extension;", 0x1, 6, 7, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Encodable;", 0x1, 8, 7, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, 9, 10, -1, -1, -1, -1 },
    { NULL, "[LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", 0x2, 11, 12, -1, -1, -1, -1 },
    { NULL, "[LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", 0x2, 13, 14, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject:withBoolean:);
  methods[1].selector = @selector(getInstanceWithId:);
  methods[2].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1Sequence:);
  methods[3].selector = @selector(initWithLibOrgBouncycastleAsn1X509Extension:);
  methods[4].selector = @selector(initWithLibOrgBouncycastleAsn1X509ExtensionArray:);
  methods[5].selector = @selector(oids);
  methods[6].selector = @selector(getExtensionWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:);
  methods[7].selector = @selector(getExtensionParsedValueWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:);
  methods[8].selector = @selector(toASN1Primitive);
  methods[9].selector = @selector(equivalentWithLibOrgBouncycastleAsn1X509Extensions:);
  methods[10].selector = @selector(getExtensionOIDs);
  methods[11].selector = @selector(getNonCriticalExtensionOIDs);
  methods[12].selector = @selector(getCriticalExtensionOIDs);
  methods[13].selector = @selector(getExtensionOIDsWithBoolean:);
  methods[14].selector = @selector(toOidArrayWithJavaUtilVector:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "extensions_", "LJavaUtilHashtable;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "ordering_", "LJavaUtilVector;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "getInstance", "LLibOrgBouncycastleAsn1ASN1TaggedObject;Z", "LNSObject;", "LLibOrgBouncycastleAsn1ASN1Sequence;", "LLibOrgBouncycastleAsn1X509Extension;", "[LLibOrgBouncycastleAsn1X509Extension;", "getExtension", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", "getExtensionParsedValue", "equivalent", "LLibOrgBouncycastleAsn1X509Extensions;", "getExtensionOIDs", "Z", "toOidArray", "LJavaUtilVector;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleAsn1X509Extensions = { "Extensions", "lib.org.bouncycastle.asn1.x509", ptrTable, methods, fields, 7, 0x1, 15, 2, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleAsn1X509Extensions;
}

@end

LibOrgBouncycastleAsn1X509Extensions *LibOrgBouncycastleAsn1X509Extensions_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(LibOrgBouncycastleAsn1ASN1TaggedObject *obj, jboolean explicit_) {
  LibOrgBouncycastleAsn1X509Extensions_initialize();
  return LibOrgBouncycastleAsn1X509Extensions_getInstanceWithId_(LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(obj, explicit_));
}

LibOrgBouncycastleAsn1X509Extensions *LibOrgBouncycastleAsn1X509Extensions_getInstanceWithId_(id obj) {
  LibOrgBouncycastleAsn1X509Extensions_initialize();
  if ([obj isKindOfClass:[LibOrgBouncycastleAsn1X509Extensions class]]) {
    return (LibOrgBouncycastleAsn1X509Extensions *) obj;
  }
  else if (obj != nil) {
    return new_LibOrgBouncycastleAsn1X509Extensions_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithId_(obj));
  }
  return nil;
}

void LibOrgBouncycastleAsn1X509Extensions_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1X509Extensions *self, LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->extensions_ = new_JavaUtilHashtable_init();
  self->ordering_ = new_JavaUtilVector_init();
  id<JavaUtilEnumeration> e = [((LibOrgBouncycastleAsn1ASN1Sequence *) nil_chk(seq)) getObjects];
  while ([((id<JavaUtilEnumeration>) nil_chk(e)) hasMoreElements]) {
    LibOrgBouncycastleAsn1X509Extension *ext = LibOrgBouncycastleAsn1X509Extension_getInstanceWithId_([e nextElement]);
    if ([((JavaUtilHashtable *) nil_chk(self->extensions_)) containsKeyWithId:[((LibOrgBouncycastleAsn1X509Extension *) nil_chk(ext)) getExtnId]]) {
      @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$@", @"repeated extension found: ", [ext getExtnId]));
    }
    (void) [((JavaUtilHashtable *) nil_chk(self->extensions_)) putWithId:[ext getExtnId] withId:ext];
    [((JavaUtilVector *) nil_chk(self->ordering_)) addElementWithId:[ext getExtnId]];
  }
}

LibOrgBouncycastleAsn1X509Extensions *new_LibOrgBouncycastleAsn1X509Extensions_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1X509Extensions, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

LibOrgBouncycastleAsn1X509Extensions *create_LibOrgBouncycastleAsn1X509Extensions_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1X509Extensions, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

void LibOrgBouncycastleAsn1X509Extensions_initWithLibOrgBouncycastleAsn1X509Extension_(LibOrgBouncycastleAsn1X509Extensions *self, LibOrgBouncycastleAsn1X509Extension *extension) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->extensions_ = new_JavaUtilHashtable_init();
  self->ordering_ = new_JavaUtilVector_init();
  [self->ordering_ addElementWithId:[((LibOrgBouncycastleAsn1X509Extension *) nil_chk(extension)) getExtnId]];
  (void) [((JavaUtilHashtable *) nil_chk(self->extensions_)) putWithId:[extension getExtnId] withId:extension];
}

LibOrgBouncycastleAsn1X509Extensions *new_LibOrgBouncycastleAsn1X509Extensions_initWithLibOrgBouncycastleAsn1X509Extension_(LibOrgBouncycastleAsn1X509Extension *extension) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1X509Extensions, initWithLibOrgBouncycastleAsn1X509Extension_, extension)
}

LibOrgBouncycastleAsn1X509Extensions *create_LibOrgBouncycastleAsn1X509Extensions_initWithLibOrgBouncycastleAsn1X509Extension_(LibOrgBouncycastleAsn1X509Extension *extension) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1X509Extensions, initWithLibOrgBouncycastleAsn1X509Extension_, extension)
}

void LibOrgBouncycastleAsn1X509Extensions_initWithLibOrgBouncycastleAsn1X509ExtensionArray_(LibOrgBouncycastleAsn1X509Extensions *self, IOSObjectArray *extensions) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->extensions_ = new_JavaUtilHashtable_init();
  self->ordering_ = new_JavaUtilVector_init();
  for (jint i = 0; i != ((IOSObjectArray *) nil_chk(extensions))->size_; i++) {
    LibOrgBouncycastleAsn1X509Extension *ext = IOSObjectArray_Get(extensions, i);
    [((JavaUtilVector *) nil_chk(self->ordering_)) addElementWithId:[((LibOrgBouncycastleAsn1X509Extension *) nil_chk(ext)) getExtnId]];
    (void) [((JavaUtilHashtable *) nil_chk(self->extensions_)) putWithId:[ext getExtnId] withId:ext];
  }
}

LibOrgBouncycastleAsn1X509Extensions *new_LibOrgBouncycastleAsn1X509Extensions_initWithLibOrgBouncycastleAsn1X509ExtensionArray_(IOSObjectArray *extensions) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1X509Extensions, initWithLibOrgBouncycastleAsn1X509ExtensionArray_, extensions)
}

LibOrgBouncycastleAsn1X509Extensions *create_LibOrgBouncycastleAsn1X509Extensions_initWithLibOrgBouncycastleAsn1X509ExtensionArray_(IOSObjectArray *extensions) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1X509Extensions, initWithLibOrgBouncycastleAsn1X509ExtensionArray_, extensions)
}

IOSObjectArray *LibOrgBouncycastleAsn1X509Extensions_getExtensionOIDsWithBoolean_(LibOrgBouncycastleAsn1X509Extensions *self, jboolean isCritical) {
  JavaUtilVector *oidVec = new_JavaUtilVector_init();
  for (jint i = 0; i != [((JavaUtilVector *) nil_chk(self->ordering_)) size]; i++) {
    id oid = [((JavaUtilVector *) nil_chk(self->ordering_)) elementAtWithInt:i];
    if ([((LibOrgBouncycastleAsn1X509Extension *) nil_chk(((LibOrgBouncycastleAsn1X509Extension *) cast_chk([((JavaUtilHashtable *) nil_chk(self->extensions_)) getWithId:oid], [LibOrgBouncycastleAsn1X509Extension class])))) isCritical] == isCritical) {
      [oidVec addElementWithId:oid];
    }
  }
  return LibOrgBouncycastleAsn1X509Extensions_toOidArrayWithJavaUtilVector_(self, oidVec);
}

IOSObjectArray *LibOrgBouncycastleAsn1X509Extensions_toOidArrayWithJavaUtilVector_(LibOrgBouncycastleAsn1X509Extensions *self, JavaUtilVector *oidVec) {
  IOSObjectArray *oids = [IOSObjectArray newArrayWithLength:[((JavaUtilVector *) nil_chk(oidVec)) size] type:LibOrgBouncycastleAsn1ASN1ObjectIdentifier_class_()];
  for (jint i = 0; i != oids->size_; i++) {
    (void) IOSObjectArray_Set(oids, i, (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *) cast_chk([oidVec elementAtWithInt:i], [LibOrgBouncycastleAsn1ASN1ObjectIdentifier class]));
  }
  return oids;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleAsn1X509Extensions)
