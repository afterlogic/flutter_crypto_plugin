//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/ASN1Object.java
//

#include "ASN1Encodable.h"
#include "ASN1Encoding.h"
#include "ASN1Object.h"
#include "ASN1OutputStream.h"
#include "ASN1Primitive.h"
#include "DEROutputStream.h"
#include "DLOutputStream.h"
#include "IOSClass.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "java/io/ByteArrayOutputStream.h"

@implementation LibOrgBouncycastleAsn1ASN1Object

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (IOSByteArray *)getEncoded {
  JavaIoByteArrayOutputStream *bOut = new_JavaIoByteArrayOutputStream_init();
  LibOrgBouncycastleAsn1ASN1OutputStream *aOut = new_LibOrgBouncycastleAsn1ASN1OutputStream_initWithJavaIoOutputStream_(bOut);
  [aOut writeObjectWithLibOrgBouncycastleAsn1ASN1Encodable:self];
  return [bOut toByteArray];
}

- (IOSByteArray *)getEncodedWithNSString:(NSString *)encoding {
  if ([((NSString *) nil_chk(encoding)) isEqual:LibOrgBouncycastleAsn1ASN1Encoding_DER]) {
    JavaIoByteArrayOutputStream *bOut = new_JavaIoByteArrayOutputStream_init();
    LibOrgBouncycastleAsn1DEROutputStream *dOut = new_LibOrgBouncycastleAsn1DEROutputStream_initWithJavaIoOutputStream_(bOut);
    [dOut writeObjectWithLibOrgBouncycastleAsn1ASN1Encodable:self];
    return [bOut toByteArray];
  }
  else if ([encoding isEqual:LibOrgBouncycastleAsn1ASN1Encoding_DL]) {
    JavaIoByteArrayOutputStream *bOut = new_JavaIoByteArrayOutputStream_init();
    LibOrgBouncycastleAsn1DLOutputStream *dOut = new_LibOrgBouncycastleAsn1DLOutputStream_initWithJavaIoOutputStream_(bOut);
    [dOut writeObjectWithLibOrgBouncycastleAsn1ASN1Encodable:self];
    return [bOut toByteArray];
  }
  return [self getEncoded];
}

- (NSUInteger)hash {
  return ((jint) [((LibOrgBouncycastleAsn1ASN1Primitive *) nil_chk([self toASN1Primitive])) hash]);
}

- (jboolean)isEqual:(id)o {
  if (self == o) {
    return true;
  }
  if (!([LibOrgBouncycastleAsn1ASN1Encodable_class_() isInstance:o])) {
    return false;
  }
  id<LibOrgBouncycastleAsn1ASN1Encodable> other = (id<LibOrgBouncycastleAsn1ASN1Encodable>) cast_check(o, LibOrgBouncycastleAsn1ASN1Encodable_class_());
  return [((LibOrgBouncycastleAsn1ASN1Primitive *) nil_chk([self toASN1Primitive])) isEqual:[((id<LibOrgBouncycastleAsn1ASN1Encodable>) nil_chk(other)) toASN1Primitive]];
}

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Object {
  return [self toASN1Primitive];
}

+ (jboolean)hasEncodedTagValueWithId:(id)obj
                             withInt:(jint)tagValue {
  return LibOrgBouncycastleAsn1ASN1Object_hasEncodedTagValueWithId_withInt_(obj, tagValue);
}

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive {
  // can't call an abstract method
  [self doesNotRecognizeSelector:_cmd];
  return 0;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, 0, -1, -1, -1 },
    { NULL, "[B", 0x1, 1, 2, 0, -1, -1, -1 },
    { NULL, "I", 0x1, 3, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, 4, 5, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0xc, 6, 7, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Primitive;", 0x401, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(getEncoded);
  methods[2].selector = @selector(getEncodedWithNSString:);
  methods[3].selector = @selector(hash);
  methods[4].selector = @selector(isEqual:);
  methods[5].selector = @selector(toASN1Object);
  methods[6].selector = @selector(hasEncodedTagValueWithId:withInt:);
  methods[7].selector = @selector(toASN1Primitive);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "LJavaIoIOException;", "getEncoded", "LNSString;", "hashCode", "equals", "LNSObject;", "hasEncodedTagValue", "LNSObject;I" };
  static const J2ObjcClassInfo _LibOrgBouncycastleAsn1ASN1Object = { "ASN1Object", "lib.org.bouncycastle.asn1", ptrTable, methods, NULL, 7, 0x401, 8, 0, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleAsn1ASN1Object;
}

@end

void LibOrgBouncycastleAsn1ASN1Object_init(LibOrgBouncycastleAsn1ASN1Object *self) {
  NSObject_init(self);
}

jboolean LibOrgBouncycastleAsn1ASN1Object_hasEncodedTagValueWithId_withInt_(id obj, jint tagValue) {
  LibOrgBouncycastleAsn1ASN1Object_initialize();
  return ([obj isKindOfClass:[IOSByteArray class]]) && IOSByteArray_Get(nil_chk(((IOSByteArray *) cast_chk(obj, [IOSByteArray class]))), 0) == tagValue;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleAsn1ASN1Object)
