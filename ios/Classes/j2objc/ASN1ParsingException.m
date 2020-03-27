//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/ASN1ParsingException.java
//

#include "ASN1ParsingException.h"
#include "J2ObjC_source.h"
#include "java/lang/IllegalStateException.h"
#include "java/lang/Throwable.h"

@interface LibOrgBouncycastleAsn1ASN1ParsingException () {
 @public
  JavaLangThrowable *cause_ASN1ParsingException_;
}

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1ASN1ParsingException, cause_ASN1ParsingException_, JavaLangThrowable *)

@implementation LibOrgBouncycastleAsn1ASN1ParsingException

- (instancetype)initWithNSString:(NSString *)message {
  LibOrgBouncycastleAsn1ASN1ParsingException_initWithNSString_(self, message);
  return self;
}

- (instancetype)initWithNSString:(NSString *)message
           withJavaLangThrowable:(JavaLangThrowable *)cause {
  LibOrgBouncycastleAsn1ASN1ParsingException_initWithNSString_withJavaLangThrowable_(self, message, cause);
  return self;
}

- (JavaLangThrowable *)getCause {
  return cause_ASN1ParsingException_;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 1, -1, -1, -1, -1 },
    { NULL, "LJavaLangThrowable;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithNSString:);
  methods[1].selector = @selector(initWithNSString:withJavaLangThrowable:);
  methods[2].selector = @selector(getCause);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "cause_ASN1ParsingException_", "LJavaLangThrowable;", .constantValue.asLong = 0, 0x2, 2, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LNSString;", "LNSString;LJavaLangThrowable;", "cause" };
  static const J2ObjcClassInfo _LibOrgBouncycastleAsn1ASN1ParsingException = { "ASN1ParsingException", "lib.org.bouncycastle.asn1", ptrTable, methods, fields, 7, 0x1, 3, 1, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleAsn1ASN1ParsingException;
}

@end

void LibOrgBouncycastleAsn1ASN1ParsingException_initWithNSString_(LibOrgBouncycastleAsn1ASN1ParsingException *self, NSString *message) {
  JavaLangIllegalStateException_initWithNSString_(self, message);
}

LibOrgBouncycastleAsn1ASN1ParsingException *new_LibOrgBouncycastleAsn1ASN1ParsingException_initWithNSString_(NSString *message) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1ASN1ParsingException, initWithNSString_, message)
}

LibOrgBouncycastleAsn1ASN1ParsingException *create_LibOrgBouncycastleAsn1ASN1ParsingException_initWithNSString_(NSString *message) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1ASN1ParsingException, initWithNSString_, message)
}

void LibOrgBouncycastleAsn1ASN1ParsingException_initWithNSString_withJavaLangThrowable_(LibOrgBouncycastleAsn1ASN1ParsingException *self, NSString *message, JavaLangThrowable *cause) {
  JavaLangIllegalStateException_initWithNSString_(self, message);
  self->cause_ASN1ParsingException_ = cause;
}

LibOrgBouncycastleAsn1ASN1ParsingException *new_LibOrgBouncycastleAsn1ASN1ParsingException_initWithNSString_withJavaLangThrowable_(NSString *message, JavaLangThrowable *cause) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1ASN1ParsingException, initWithNSString_withJavaLangThrowable_, message, cause)
}

LibOrgBouncycastleAsn1ASN1ParsingException *create_LibOrgBouncycastleAsn1ASN1ParsingException_initWithNSString_withJavaLangThrowable_(NSString *message, JavaLangThrowable *cause) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1ASN1ParsingException, initWithNSString_withJavaLangThrowable_, message, cause)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleAsn1ASN1ParsingException)
