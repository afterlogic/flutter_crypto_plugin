//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jce/spec/RepeatedSecretKeySpec.java
//

#include "J2ObjC_source.h"
#include "JcajceRepeatedSecretKeySpec.h"
#include "RepeatedSecretKeySpec.h"

@interface LibOrgBouncycastleJceSpecRepeatedSecretKeySpec () {
 @public
  NSString *algorithm_RepeatedSecretKeySpec_;
}

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleJceSpecRepeatedSecretKeySpec, algorithm_RepeatedSecretKeySpec_, NSString *)

@implementation LibOrgBouncycastleJceSpecRepeatedSecretKeySpec

- (instancetype)initWithNSString:(NSString *)algorithm {
  LibOrgBouncycastleJceSpecRepeatedSecretKeySpec_initWithNSString_(self, algorithm);
  return self;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithNSString:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "algorithm_RepeatedSecretKeySpec_", "LNSString;", .constantValue.asLong = 0, 0x2, 1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LNSString;", "algorithm" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJceSpecRepeatedSecretKeySpec = { "RepeatedSecretKeySpec", "lib.org.bouncycastle.jce.spec", ptrTable, methods, fields, 7, 0x1, 1, 1, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJceSpecRepeatedSecretKeySpec;
}

@end

void LibOrgBouncycastleJceSpecRepeatedSecretKeySpec_initWithNSString_(LibOrgBouncycastleJceSpecRepeatedSecretKeySpec *self, NSString *algorithm) {
  LibOrgBouncycastleJcajceSpecJcajceRepeatedSecretKeySpec_initWithNSString_(self, algorithm);
}

LibOrgBouncycastleJceSpecRepeatedSecretKeySpec *new_LibOrgBouncycastleJceSpecRepeatedSecretKeySpec_initWithNSString_(NSString *algorithm) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJceSpecRepeatedSecretKeySpec, initWithNSString_, algorithm)
}

LibOrgBouncycastleJceSpecRepeatedSecretKeySpec *create_LibOrgBouncycastleJceSpecRepeatedSecretKeySpec_initWithNSString_(NSString *algorithm) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJceSpecRepeatedSecretKeySpec, initWithNSString_, algorithm)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJceSpecRepeatedSecretKeySpec)
