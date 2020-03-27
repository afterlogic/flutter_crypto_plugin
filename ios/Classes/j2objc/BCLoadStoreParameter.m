//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jcajce/BCLoadStoreParameter.java
//

#include "BCLoadStoreParameter.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "java/io/InputStream.h"
#include "java/io/OutputStream.h"
#include "java/lang/UnsupportedOperationException.h"
#include "java/security/KeyStore.h"

@interface LibOrgBouncycastleJcajceBCLoadStoreParameter () {
 @public
  JavaIoInputStream *in_;
  JavaIoOutputStream *out_;
  id<JavaSecurityKeyStore_ProtectionParameter> protectionParameter_;
}

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleJcajceBCLoadStoreParameter, in_, JavaIoInputStream *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleJcajceBCLoadStoreParameter, out_, JavaIoOutputStream *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleJcajceBCLoadStoreParameter, protectionParameter_, id<JavaSecurityKeyStore_ProtectionParameter>)

@implementation LibOrgBouncycastleJcajceBCLoadStoreParameter

- (instancetype)initWithJavaIoOutputStream:(JavaIoOutputStream *)outArg
                             withCharArray:(IOSCharArray *)password {
  LibOrgBouncycastleJcajceBCLoadStoreParameter_initWithJavaIoOutputStream_withCharArray_(self, outArg, password);
  return self;
}

- (instancetype)initWithJavaIoInputStream:(JavaIoInputStream *)inArg
                            withCharArray:(IOSCharArray *)password {
  LibOrgBouncycastleJcajceBCLoadStoreParameter_initWithJavaIoInputStream_withCharArray_(self, inArg, password);
  return self;
}

- (instancetype)initWithJavaIoInputStream:(JavaIoInputStream *)inArg
withJavaSecurityKeyStore_ProtectionParameter:(id<JavaSecurityKeyStore_ProtectionParameter>)protectionParameter {
  LibOrgBouncycastleJcajceBCLoadStoreParameter_initWithJavaIoInputStream_withJavaSecurityKeyStore_ProtectionParameter_(self, inArg, protectionParameter);
  return self;
}

- (instancetype)initWithJavaIoOutputStream:(JavaIoOutputStream *)outArg
withJavaSecurityKeyStore_ProtectionParameter:(id<JavaSecurityKeyStore_ProtectionParameter>)protectionParameter {
  LibOrgBouncycastleJcajceBCLoadStoreParameter_initWithJavaIoOutputStream_withJavaSecurityKeyStore_ProtectionParameter_(self, outArg, protectionParameter);
  return self;
}

- (instancetype)initWithJavaIoInputStream:(JavaIoInputStream *)inArg
                   withJavaIoOutputStream:(JavaIoOutputStream *)outArg
withJavaSecurityKeyStore_ProtectionParameter:(id<JavaSecurityKeyStore_ProtectionParameter>)protectionParameter {
  LibOrgBouncycastleJcajceBCLoadStoreParameter_initWithJavaIoInputStream_withJavaIoOutputStream_withJavaSecurityKeyStore_ProtectionParameter_(self, inArg, outArg, protectionParameter);
  return self;
}

- (id<JavaSecurityKeyStore_ProtectionParameter>)getProtectionParameter {
  return protectionParameter_;
}

- (JavaIoOutputStream *)getOutputStream {
  if (out_ == nil) {
    @throw new_JavaLangUnsupportedOperationException_initWithNSString_(@"parameter not configured for storage - no OutputStream");
  }
  return out_;
}

- (JavaIoInputStream *)getInputStream {
  if (out_ != nil) {
    @throw new_JavaLangUnsupportedOperationException_initWithNSString_(@"parameter configured for storage OutputStream present");
  }
  return in_;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 1, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 2, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 3, -1, -1, -1, -1 },
    { NULL, NULL, 0x0, -1, 4, -1, -1, -1, -1 },
    { NULL, "LJavaSecurityKeyStore_ProtectionParameter;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LJavaIoOutputStream;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LJavaIoInputStream;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithJavaIoOutputStream:withCharArray:);
  methods[1].selector = @selector(initWithJavaIoInputStream:withCharArray:);
  methods[2].selector = @selector(initWithJavaIoInputStream:withJavaSecurityKeyStore_ProtectionParameter:);
  methods[3].selector = @selector(initWithJavaIoOutputStream:withJavaSecurityKeyStore_ProtectionParameter:);
  methods[4].selector = @selector(initWithJavaIoInputStream:withJavaIoOutputStream:withJavaSecurityKeyStore_ProtectionParameter:);
  methods[5].selector = @selector(getProtectionParameter);
  methods[6].selector = @selector(getOutputStream);
  methods[7].selector = @selector(getInputStream);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "in_", "LJavaIoInputStream;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "out_", "LJavaIoOutputStream;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "protectionParameter_", "LJavaSecurityKeyStore_ProtectionParameter;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LJavaIoOutputStream;[C", "LJavaIoInputStream;[C", "LJavaIoInputStream;LJavaSecurityKeyStore_ProtectionParameter;", "LJavaIoOutputStream;LJavaSecurityKeyStore_ProtectionParameter;", "LJavaIoInputStream;LJavaIoOutputStream;LJavaSecurityKeyStore_ProtectionParameter;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceBCLoadStoreParameter = { "BCLoadStoreParameter", "lib.org.bouncycastle.jcajce", ptrTable, methods, fields, 7, 0x1, 8, 3, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceBCLoadStoreParameter;
}

@end

void LibOrgBouncycastleJcajceBCLoadStoreParameter_initWithJavaIoOutputStream_withCharArray_(LibOrgBouncycastleJcajceBCLoadStoreParameter *self, JavaIoOutputStream *outArg, IOSCharArray *password) {
  LibOrgBouncycastleJcajceBCLoadStoreParameter_initWithJavaIoOutputStream_withJavaSecurityKeyStore_ProtectionParameter_(self, outArg, new_JavaSecurityKeyStore_PasswordProtection_initWithCharArray_(password));
}

LibOrgBouncycastleJcajceBCLoadStoreParameter *new_LibOrgBouncycastleJcajceBCLoadStoreParameter_initWithJavaIoOutputStream_withCharArray_(JavaIoOutputStream *outArg, IOSCharArray *password) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceBCLoadStoreParameter, initWithJavaIoOutputStream_withCharArray_, outArg, password)
}

LibOrgBouncycastleJcajceBCLoadStoreParameter *create_LibOrgBouncycastleJcajceBCLoadStoreParameter_initWithJavaIoOutputStream_withCharArray_(JavaIoOutputStream *outArg, IOSCharArray *password) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceBCLoadStoreParameter, initWithJavaIoOutputStream_withCharArray_, outArg, password)
}

void LibOrgBouncycastleJcajceBCLoadStoreParameter_initWithJavaIoInputStream_withCharArray_(LibOrgBouncycastleJcajceBCLoadStoreParameter *self, JavaIoInputStream *inArg, IOSCharArray *password) {
  LibOrgBouncycastleJcajceBCLoadStoreParameter_initWithJavaIoInputStream_withJavaSecurityKeyStore_ProtectionParameter_(self, inArg, new_JavaSecurityKeyStore_PasswordProtection_initWithCharArray_(password));
}

LibOrgBouncycastleJcajceBCLoadStoreParameter *new_LibOrgBouncycastleJcajceBCLoadStoreParameter_initWithJavaIoInputStream_withCharArray_(JavaIoInputStream *inArg, IOSCharArray *password) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceBCLoadStoreParameter, initWithJavaIoInputStream_withCharArray_, inArg, password)
}

LibOrgBouncycastleJcajceBCLoadStoreParameter *create_LibOrgBouncycastleJcajceBCLoadStoreParameter_initWithJavaIoInputStream_withCharArray_(JavaIoInputStream *inArg, IOSCharArray *password) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceBCLoadStoreParameter, initWithJavaIoInputStream_withCharArray_, inArg, password)
}

void LibOrgBouncycastleJcajceBCLoadStoreParameter_initWithJavaIoInputStream_withJavaSecurityKeyStore_ProtectionParameter_(LibOrgBouncycastleJcajceBCLoadStoreParameter *self, JavaIoInputStream *inArg, id<JavaSecurityKeyStore_ProtectionParameter> protectionParameter) {
  LibOrgBouncycastleJcajceBCLoadStoreParameter_initWithJavaIoInputStream_withJavaIoOutputStream_withJavaSecurityKeyStore_ProtectionParameter_(self, inArg, nil, protectionParameter);
}

LibOrgBouncycastleJcajceBCLoadStoreParameter *new_LibOrgBouncycastleJcajceBCLoadStoreParameter_initWithJavaIoInputStream_withJavaSecurityKeyStore_ProtectionParameter_(JavaIoInputStream *inArg, id<JavaSecurityKeyStore_ProtectionParameter> protectionParameter) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceBCLoadStoreParameter, initWithJavaIoInputStream_withJavaSecurityKeyStore_ProtectionParameter_, inArg, protectionParameter)
}

LibOrgBouncycastleJcajceBCLoadStoreParameter *create_LibOrgBouncycastleJcajceBCLoadStoreParameter_initWithJavaIoInputStream_withJavaSecurityKeyStore_ProtectionParameter_(JavaIoInputStream *inArg, id<JavaSecurityKeyStore_ProtectionParameter> protectionParameter) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceBCLoadStoreParameter, initWithJavaIoInputStream_withJavaSecurityKeyStore_ProtectionParameter_, inArg, protectionParameter)
}

void LibOrgBouncycastleJcajceBCLoadStoreParameter_initWithJavaIoOutputStream_withJavaSecurityKeyStore_ProtectionParameter_(LibOrgBouncycastleJcajceBCLoadStoreParameter *self, JavaIoOutputStream *outArg, id<JavaSecurityKeyStore_ProtectionParameter> protectionParameter) {
  LibOrgBouncycastleJcajceBCLoadStoreParameter_initWithJavaIoInputStream_withJavaIoOutputStream_withJavaSecurityKeyStore_ProtectionParameter_(self, nil, outArg, protectionParameter);
}

LibOrgBouncycastleJcajceBCLoadStoreParameter *new_LibOrgBouncycastleJcajceBCLoadStoreParameter_initWithJavaIoOutputStream_withJavaSecurityKeyStore_ProtectionParameter_(JavaIoOutputStream *outArg, id<JavaSecurityKeyStore_ProtectionParameter> protectionParameter) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceBCLoadStoreParameter, initWithJavaIoOutputStream_withJavaSecurityKeyStore_ProtectionParameter_, outArg, protectionParameter)
}

LibOrgBouncycastleJcajceBCLoadStoreParameter *create_LibOrgBouncycastleJcajceBCLoadStoreParameter_initWithJavaIoOutputStream_withJavaSecurityKeyStore_ProtectionParameter_(JavaIoOutputStream *outArg, id<JavaSecurityKeyStore_ProtectionParameter> protectionParameter) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceBCLoadStoreParameter, initWithJavaIoOutputStream_withJavaSecurityKeyStore_ProtectionParameter_, outArg, protectionParameter)
}

void LibOrgBouncycastleJcajceBCLoadStoreParameter_initWithJavaIoInputStream_withJavaIoOutputStream_withJavaSecurityKeyStore_ProtectionParameter_(LibOrgBouncycastleJcajceBCLoadStoreParameter *self, JavaIoInputStream *inArg, JavaIoOutputStream *outArg, id<JavaSecurityKeyStore_ProtectionParameter> protectionParameter) {
  NSObject_init(self);
  self->in_ = inArg;
  self->out_ = outArg;
  self->protectionParameter_ = protectionParameter;
}

LibOrgBouncycastleJcajceBCLoadStoreParameter *new_LibOrgBouncycastleJcajceBCLoadStoreParameter_initWithJavaIoInputStream_withJavaIoOutputStream_withJavaSecurityKeyStore_ProtectionParameter_(JavaIoInputStream *inArg, JavaIoOutputStream *outArg, id<JavaSecurityKeyStore_ProtectionParameter> protectionParameter) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceBCLoadStoreParameter, initWithJavaIoInputStream_withJavaIoOutputStream_withJavaSecurityKeyStore_ProtectionParameter_, inArg, outArg, protectionParameter)
}

LibOrgBouncycastleJcajceBCLoadStoreParameter *create_LibOrgBouncycastleJcajceBCLoadStoreParameter_initWithJavaIoInputStream_withJavaIoOutputStream_withJavaSecurityKeyStore_ProtectionParameter_(JavaIoInputStream *inArg, JavaIoOutputStream *outArg, id<JavaSecurityKeyStore_ProtectionParameter> protectionParameter) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceBCLoadStoreParameter, initWithJavaIoInputStream_withJavaIoOutputStream_withJavaSecurityKeyStore_ProtectionParameter_, inArg, outArg, protectionParameter)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceBCLoadStoreParameter)
