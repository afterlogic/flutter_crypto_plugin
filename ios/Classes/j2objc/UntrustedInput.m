//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/i18n/filter/UntrustedInput.java
//

#include "J2ObjC_source.h"
#include "UntrustedInput.h"

@implementation LibOrgBouncycastleI18nFilterUntrustedInput

- (instancetype)initWithId:(id)input {
  LibOrgBouncycastleI18nFilterUntrustedInput_initWithId_(self, input);
  return self;
}

- (id)getInput {
  return input_;
}

- (NSString *)getString {
  return [nil_chk(input_) description];
}

- (NSString *)description {
  return [nil_chk(input_) description];
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "LNSObject;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x1, 1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithId:);
  methods[1].selector = @selector(getInput);
  methods[2].selector = @selector(getString);
  methods[3].selector = @selector(description);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "input_", "LNSObject;", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LNSObject;", "toString" };
  static const J2ObjcClassInfo _LibOrgBouncycastleI18nFilterUntrustedInput = { "UntrustedInput", "lib.org.bouncycastle.i18n.filter", ptrTable, methods, fields, 7, 0x1, 4, 1, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleI18nFilterUntrustedInput;
}

@end

void LibOrgBouncycastleI18nFilterUntrustedInput_initWithId_(LibOrgBouncycastleI18nFilterUntrustedInput *self, id input) {
  NSObject_init(self);
  self->input_ = input;
}

LibOrgBouncycastleI18nFilterUntrustedInput *new_LibOrgBouncycastleI18nFilterUntrustedInput_initWithId_(id input) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleI18nFilterUntrustedInput, initWithId_, input)
}

LibOrgBouncycastleI18nFilterUntrustedInput *create_LibOrgBouncycastleI18nFilterUntrustedInput_initWithId_(id input) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleI18nFilterUntrustedInput, initWithId_, input)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleI18nFilterUntrustedInput)
