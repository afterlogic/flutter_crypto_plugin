//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/util/DERDump.java
//

#include "ASN1Dump.h"
#include "ASN1Encodable.h"
#include "ASN1Primitive.h"
#include "DERDump.h"
#include "J2ObjC_source.h"
#include "java/lang/StringBuffer.h"

@implementation LibOrgBouncycastleAsn1UtilDERDump

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleAsn1UtilDERDump_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

+ (NSString *)dumpAsStringWithLibOrgBouncycastleAsn1ASN1Primitive:(LibOrgBouncycastleAsn1ASN1Primitive *)obj {
  return LibOrgBouncycastleAsn1UtilDERDump_dumpAsStringWithLibOrgBouncycastleAsn1ASN1Primitive_(obj);
}

+ (NSString *)dumpAsStringWithLibOrgBouncycastleAsn1ASN1Encodable:(id<LibOrgBouncycastleAsn1ASN1Encodable>)obj {
  return LibOrgBouncycastleAsn1UtilDERDump_dumpAsStringWithLibOrgBouncycastleAsn1ASN1Encodable_(obj);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x9, 0, 1, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x9, 0, 2, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(dumpAsStringWithLibOrgBouncycastleAsn1ASN1Primitive:);
  methods[2].selector = @selector(dumpAsStringWithLibOrgBouncycastleAsn1ASN1Encodable:);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "dumpAsString", "LLibOrgBouncycastleAsn1ASN1Primitive;", "LLibOrgBouncycastleAsn1ASN1Encodable;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleAsn1UtilDERDump = { "DERDump", "lib.org.bouncycastle.asn1.util", ptrTable, methods, NULL, 7, 0x1, 3, 0, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleAsn1UtilDERDump;
}

@end

void LibOrgBouncycastleAsn1UtilDERDump_init(LibOrgBouncycastleAsn1UtilDERDump *self) {
  LibOrgBouncycastleAsn1UtilASN1Dump_init(self);
}

LibOrgBouncycastleAsn1UtilDERDump *new_LibOrgBouncycastleAsn1UtilDERDump_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1UtilDERDump, init)
}

LibOrgBouncycastleAsn1UtilDERDump *create_LibOrgBouncycastleAsn1UtilDERDump_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1UtilDERDump, init)
}

NSString *LibOrgBouncycastleAsn1UtilDERDump_dumpAsStringWithLibOrgBouncycastleAsn1ASN1Primitive_(LibOrgBouncycastleAsn1ASN1Primitive *obj) {
  LibOrgBouncycastleAsn1UtilDERDump_initialize();
  JavaLangStringBuffer *buf = new_JavaLangStringBuffer_init();
  LibOrgBouncycastleAsn1UtilASN1Dump__dumpAsStringWithNSString_withBoolean_withLibOrgBouncycastleAsn1ASN1Primitive_withJavaLangStringBuffer_(@"", false, obj, buf);
  return [buf description];
}

NSString *LibOrgBouncycastleAsn1UtilDERDump_dumpAsStringWithLibOrgBouncycastleAsn1ASN1Encodable_(id<LibOrgBouncycastleAsn1ASN1Encodable> obj) {
  LibOrgBouncycastleAsn1UtilDERDump_initialize();
  JavaLangStringBuffer *buf = new_JavaLangStringBuffer_init();
  LibOrgBouncycastleAsn1UtilASN1Dump__dumpAsStringWithNSString_withBoolean_withLibOrgBouncycastleAsn1ASN1Primitive_withJavaLangStringBuffer_(@"", false, [((id<LibOrgBouncycastleAsn1ASN1Encodable>) nil_chk(obj)) toASN1Primitive], buf);
  return [buf description];
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleAsn1UtilDERDump)