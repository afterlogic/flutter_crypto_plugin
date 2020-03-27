//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jcajce/provider/symmetric/util/ClassUtil.java
//

#include "ClassUtil.h"
#include "IOSClass.h"
#include "J2ObjC_source.h"
#include "java/lang/ClassLoader.h"
#include "java/lang/ClassNotFoundException.h"
#include "java/lang/Exception.h"
#include "java/security/AccessController.h"
#include "java/security/PrivilegedAction.h"

@interface LibOrgBouncycastleJcajceProviderSymmetricUtilClassUtil_1 : NSObject < JavaSecurityPrivilegedAction > {
 @public
  NSString *val$className_;
}

- (instancetype)initWithNSString:(NSString *)capture$0;

- (id)run;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderSymmetricUtilClassUtil_1)

__attribute__((unused)) static void LibOrgBouncycastleJcajceProviderSymmetricUtilClassUtil_1_initWithNSString_(LibOrgBouncycastleJcajceProviderSymmetricUtilClassUtil_1 *self, NSString *capture$0);

__attribute__((unused)) static LibOrgBouncycastleJcajceProviderSymmetricUtilClassUtil_1 *new_LibOrgBouncycastleJcajceProviderSymmetricUtilClassUtil_1_initWithNSString_(NSString *capture$0) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleJcajceProviderSymmetricUtilClassUtil_1 *create_LibOrgBouncycastleJcajceProviderSymmetricUtilClassUtil_1_initWithNSString_(NSString *capture$0);

@implementation LibOrgBouncycastleJcajceProviderSymmetricUtilClassUtil

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceProviderSymmetricUtilClassUtil_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

+ (IOSClass *)loadClassWithIOSClass:(IOSClass *)sourceClass
                       withNSString:(NSString *)className_ {
  return LibOrgBouncycastleJcajceProviderSymmetricUtilClassUtil_loadClassWithIOSClass_withNSString_(sourceClass, className_);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LIOSClass;", 0x9, 0, 1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(loadClassWithIOSClass:withNSString:);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "loadClass", "LIOSClass;LNSString;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderSymmetricUtilClassUtil = { "ClassUtil", "lib.org.bouncycastle.jcajce.provider.symmetric.util", ptrTable, methods, NULL, 7, 0x1, 2, 0, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderSymmetricUtilClassUtil;
}

@end

void LibOrgBouncycastleJcajceProviderSymmetricUtilClassUtil_init(LibOrgBouncycastleJcajceProviderSymmetricUtilClassUtil *self) {
  NSObject_init(self);
}

LibOrgBouncycastleJcajceProviderSymmetricUtilClassUtil *new_LibOrgBouncycastleJcajceProviderSymmetricUtilClassUtil_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderSymmetricUtilClassUtil, init)
}

LibOrgBouncycastleJcajceProviderSymmetricUtilClassUtil *create_LibOrgBouncycastleJcajceProviderSymmetricUtilClassUtil_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderSymmetricUtilClassUtil, init)
}

IOSClass *LibOrgBouncycastleJcajceProviderSymmetricUtilClassUtil_loadClassWithIOSClass_withNSString_(IOSClass *sourceClass, NSString *className_) {
  LibOrgBouncycastleJcajceProviderSymmetricUtilClassUtil_initialize();
  @try {
    JavaLangClassLoader *loader = [((IOSClass *) nil_chk(sourceClass)) getClassLoader];
    if (loader != nil) {
      return [loader loadClassWithNSString:className_];
    }
    else {
      return (IOSClass *) cast_chk(JavaSecurityAccessController_doPrivilegedWithJavaSecurityPrivilegedAction_(new_LibOrgBouncycastleJcajceProviderSymmetricUtilClassUtil_1_initWithNSString_(className_)), [IOSClass class]);
    }
  }
  @catch (JavaLangClassNotFoundException *e) {
  }
  return nil;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderSymmetricUtilClassUtil)

@implementation LibOrgBouncycastleJcajceProviderSymmetricUtilClassUtil_1

- (instancetype)initWithNSString:(NSString *)capture$0 {
  LibOrgBouncycastleJcajceProviderSymmetricUtilClassUtil_1_initWithNSString_(self, capture$0);
  return self;
}

- (id)run {
  @try {
    return IOSClass_forName_(val$className_);
  }
  @catch (JavaLangException *e) {
  }
  return nil;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x0, -1, -1, -1, -1, -1, -1 },
    { NULL, "LNSObject;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithNSString:);
  methods[1].selector = @selector(run);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "val$className_", "LNSString;", .constantValue.asLong = 0, 0x1012, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleJcajceProviderSymmetricUtilClassUtil;", "loadClassWithIOSClass:withNSString:" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderSymmetricUtilClassUtil_1 = { "", "lib.org.bouncycastle.jcajce.provider.symmetric.util", ptrTable, methods, fields, 7, 0x8018, 2, 1, 0, -1, 1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderSymmetricUtilClassUtil_1;
}

@end

void LibOrgBouncycastleJcajceProviderSymmetricUtilClassUtil_1_initWithNSString_(LibOrgBouncycastleJcajceProviderSymmetricUtilClassUtil_1 *self, NSString *capture$0) {
  self->val$className_ = capture$0;
  NSObject_init(self);
}

LibOrgBouncycastleJcajceProviderSymmetricUtilClassUtil_1 *new_LibOrgBouncycastleJcajceProviderSymmetricUtilClassUtil_1_initWithNSString_(NSString *capture$0) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderSymmetricUtilClassUtil_1, initWithNSString_, capture$0)
}

LibOrgBouncycastleJcajceProviderSymmetricUtilClassUtil_1 *create_LibOrgBouncycastleJcajceProviderSymmetricUtilClassUtil_1_initWithNSString_(NSString *capture$0) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderSymmetricUtilClassUtil_1, initWithNSString_, capture$0)
}
