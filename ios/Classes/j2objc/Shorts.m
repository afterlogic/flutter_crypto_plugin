//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/util/Shorts.java
//

#include "J2ObjC_source.h"
#include "Shorts.h"
#include "java/lang/Short.h"

@implementation LibOrgBouncycastleUtilShorts

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleUtilShorts_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

+ (JavaLangShort *)valueOfWithShort:(jshort)value {
  return LibOrgBouncycastleUtilShorts_valueOfWithShort_(value);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LJavaLangShort;", 0x9, 0, 1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(valueOfWithShort:);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "valueOf", "S" };
  static const J2ObjcClassInfo _LibOrgBouncycastleUtilShorts = { "Shorts", "lib.org.bouncycastle.util", ptrTable, methods, NULL, 7, 0x1, 2, 0, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleUtilShorts;
}

@end

void LibOrgBouncycastleUtilShorts_init(LibOrgBouncycastleUtilShorts *self) {
  NSObject_init(self);
}

LibOrgBouncycastleUtilShorts *new_LibOrgBouncycastleUtilShorts_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleUtilShorts, init)
}

LibOrgBouncycastleUtilShorts *create_LibOrgBouncycastleUtilShorts_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleUtilShorts, init)
}

JavaLangShort *LibOrgBouncycastleUtilShorts_valueOfWithShort_(jshort value) {
  LibOrgBouncycastleUtilShorts_initialize();
  return JavaLangShort_valueOfWithShort_(value);
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleUtilShorts)