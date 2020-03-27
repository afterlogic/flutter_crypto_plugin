//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/crmf/SubsequentMessage.java
//

#include "ASN1Integer.h"
#include "J2ObjC_source.h"
#include "SubsequentMessage.h"
#include "java/lang/IllegalArgumentException.h"

@interface LibOrgBouncycastleAsn1CrmfSubsequentMessage ()

- (instancetype)initWithInt:(jint)value;

@end

__attribute__((unused)) static void LibOrgBouncycastleAsn1CrmfSubsequentMessage_initWithInt_(LibOrgBouncycastleAsn1CrmfSubsequentMessage *self, jint value);

__attribute__((unused)) static LibOrgBouncycastleAsn1CrmfSubsequentMessage *new_LibOrgBouncycastleAsn1CrmfSubsequentMessage_initWithInt_(jint value) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleAsn1CrmfSubsequentMessage *create_LibOrgBouncycastleAsn1CrmfSubsequentMessage_initWithInt_(jint value);

J2OBJC_INITIALIZED_DEFN(LibOrgBouncycastleAsn1CrmfSubsequentMessage)

LibOrgBouncycastleAsn1CrmfSubsequentMessage *LibOrgBouncycastleAsn1CrmfSubsequentMessage_encrCert;
LibOrgBouncycastleAsn1CrmfSubsequentMessage *LibOrgBouncycastleAsn1CrmfSubsequentMessage_challengeResp;

@implementation LibOrgBouncycastleAsn1CrmfSubsequentMessage

+ (LibOrgBouncycastleAsn1CrmfSubsequentMessage *)encrCert {
  return LibOrgBouncycastleAsn1CrmfSubsequentMessage_encrCert;
}

+ (LibOrgBouncycastleAsn1CrmfSubsequentMessage *)challengeResp {
  return LibOrgBouncycastleAsn1CrmfSubsequentMessage_challengeResp;
}

- (instancetype)initWithInt:(jint)value {
  LibOrgBouncycastleAsn1CrmfSubsequentMessage_initWithInt_(self, value);
  return self;
}

+ (LibOrgBouncycastleAsn1CrmfSubsequentMessage *)valueOfWithInt:(jint)value {
  return LibOrgBouncycastleAsn1CrmfSubsequentMessage_valueOfWithInt_(value);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x2, -1, 0, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1CrmfSubsequentMessage;", 0x9, 1, 0, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithInt:);
  methods[1].selector = @selector(valueOfWithInt:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "encrCert", "LLibOrgBouncycastleAsn1CrmfSubsequentMessage;", .constantValue.asLong = 0, 0x19, -1, 2, -1, -1 },
    { "challengeResp", "LLibOrgBouncycastleAsn1CrmfSubsequentMessage;", .constantValue.asLong = 0, 0x19, -1, 3, -1, -1 },
  };
  static const void *ptrTable[] = { "I", "valueOf", &LibOrgBouncycastleAsn1CrmfSubsequentMessage_encrCert, &LibOrgBouncycastleAsn1CrmfSubsequentMessage_challengeResp };
  static const J2ObjcClassInfo _LibOrgBouncycastleAsn1CrmfSubsequentMessage = { "SubsequentMessage", "lib.org.bouncycastle.asn1.crmf", ptrTable, methods, fields, 7, 0x1, 2, 2, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleAsn1CrmfSubsequentMessage;
}

+ (void)initialize {
  if (self == [LibOrgBouncycastleAsn1CrmfSubsequentMessage class]) {
    LibOrgBouncycastleAsn1CrmfSubsequentMessage_encrCert = new_LibOrgBouncycastleAsn1CrmfSubsequentMessage_initWithInt_(0);
    LibOrgBouncycastleAsn1CrmfSubsequentMessage_challengeResp = new_LibOrgBouncycastleAsn1CrmfSubsequentMessage_initWithInt_(1);
    J2OBJC_SET_INITIALIZED(LibOrgBouncycastleAsn1CrmfSubsequentMessage)
  }
}

@end

void LibOrgBouncycastleAsn1CrmfSubsequentMessage_initWithInt_(LibOrgBouncycastleAsn1CrmfSubsequentMessage *self, jint value) {
  LibOrgBouncycastleAsn1ASN1Integer_initWithLong_(self, value);
}

LibOrgBouncycastleAsn1CrmfSubsequentMessage *new_LibOrgBouncycastleAsn1CrmfSubsequentMessage_initWithInt_(jint value) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1CrmfSubsequentMessage, initWithInt_, value)
}

LibOrgBouncycastleAsn1CrmfSubsequentMessage *create_LibOrgBouncycastleAsn1CrmfSubsequentMessage_initWithInt_(jint value) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1CrmfSubsequentMessage, initWithInt_, value)
}

LibOrgBouncycastleAsn1CrmfSubsequentMessage *LibOrgBouncycastleAsn1CrmfSubsequentMessage_valueOfWithInt_(jint value) {
  LibOrgBouncycastleAsn1CrmfSubsequentMessage_initialize();
  if (value == 0) {
    return LibOrgBouncycastleAsn1CrmfSubsequentMessage_encrCert;
  }
  if (value == 1) {
    return LibOrgBouncycastleAsn1CrmfSubsequentMessage_challengeResp;
  }
  @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$I", @"unknown value: ", value));
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleAsn1CrmfSubsequentMessage)
