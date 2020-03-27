//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jce/spec/MQVPrivateKeySpec.java
//

#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "MQVPrivateKeySpec.h"
#include "java/security/PrivateKey.h"
#include "java/security/PublicKey.h"
#include "javax/security/auth/Destroyable.h"

@interface LibOrgBouncycastleJceSpecMQVPrivateKeySpec () {
 @public
  id<JavaSecurityPrivateKey> staticPrivateKey_;
  id<JavaSecurityPrivateKey> ephemeralPrivateKey_;
  id<JavaSecurityPublicKey> ephemeralPublicKey_;
}

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleJceSpecMQVPrivateKeySpec, staticPrivateKey_, id<JavaSecurityPrivateKey>)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleJceSpecMQVPrivateKeySpec, ephemeralPrivateKey_, id<JavaSecurityPrivateKey>)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleJceSpecMQVPrivateKeySpec, ephemeralPublicKey_, id<JavaSecurityPublicKey>)

@implementation LibOrgBouncycastleJceSpecMQVPrivateKeySpec

- (instancetype)initWithJavaSecurityPrivateKey:(id<JavaSecurityPrivateKey>)staticPrivateKey
                    withJavaSecurityPrivateKey:(id<JavaSecurityPrivateKey>)ephemeralPrivateKey {
  LibOrgBouncycastleJceSpecMQVPrivateKeySpec_initWithJavaSecurityPrivateKey_withJavaSecurityPrivateKey_(self, staticPrivateKey, ephemeralPrivateKey);
  return self;
}

- (instancetype)initWithJavaSecurityPrivateKey:(id<JavaSecurityPrivateKey>)staticPrivateKey
                    withJavaSecurityPrivateKey:(id<JavaSecurityPrivateKey>)ephemeralPrivateKey
                     withJavaSecurityPublicKey:(id<JavaSecurityPublicKey>)ephemeralPublicKey {
  LibOrgBouncycastleJceSpecMQVPrivateKeySpec_initWithJavaSecurityPrivateKey_withJavaSecurityPrivateKey_withJavaSecurityPublicKey_(self, staticPrivateKey, ephemeralPrivateKey, ephemeralPublicKey);
  return self;
}

- (id<JavaSecurityPrivateKey>)getStaticPrivateKey {
  return staticPrivateKey_;
}

- (id<JavaSecurityPrivateKey>)getEphemeralPrivateKey {
  return ephemeralPrivateKey_;
}

- (id<JavaSecurityPublicKey>)getEphemeralPublicKey {
  return ephemeralPublicKey_;
}

- (NSString *)getAlgorithm {
  return @"ECMQV";
}

- (NSString *)getFormat {
  return nil;
}

- (IOSByteArray *)getEncoded {
  return nil;
}

- (void)destroy {
  JavaxSecurityAuthDestroyable_destroy(self);
}

- (jboolean)isDestroyed {
  return JavaxSecurityAuthDestroyable_isDestroyed(self);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 1, -1, -1, -1, -1 },
    { NULL, "LJavaSecurityPrivateKey;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LJavaSecurityPrivateKey;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LJavaSecurityPublicKey;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithJavaSecurityPrivateKey:withJavaSecurityPrivateKey:);
  methods[1].selector = @selector(initWithJavaSecurityPrivateKey:withJavaSecurityPrivateKey:withJavaSecurityPublicKey:);
  methods[2].selector = @selector(getStaticPrivateKey);
  methods[3].selector = @selector(getEphemeralPrivateKey);
  methods[4].selector = @selector(getEphemeralPublicKey);
  methods[5].selector = @selector(getAlgorithm);
  methods[6].selector = @selector(getFormat);
  methods[7].selector = @selector(getEncoded);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "staticPrivateKey_", "LJavaSecurityPrivateKey;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "ephemeralPrivateKey_", "LJavaSecurityPrivateKey;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "ephemeralPublicKey_", "LJavaSecurityPublicKey;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LJavaSecurityPrivateKey;LJavaSecurityPrivateKey;", "LJavaSecurityPrivateKey;LJavaSecurityPrivateKey;LJavaSecurityPublicKey;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJceSpecMQVPrivateKeySpec = { "MQVPrivateKeySpec", "lib.org.bouncycastle.jce.spec", ptrTable, methods, fields, 7, 0x1, 8, 3, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJceSpecMQVPrivateKeySpec;
}

@end

void LibOrgBouncycastleJceSpecMQVPrivateKeySpec_initWithJavaSecurityPrivateKey_withJavaSecurityPrivateKey_(LibOrgBouncycastleJceSpecMQVPrivateKeySpec *self, id<JavaSecurityPrivateKey> staticPrivateKey, id<JavaSecurityPrivateKey> ephemeralPrivateKey) {
  LibOrgBouncycastleJceSpecMQVPrivateKeySpec_initWithJavaSecurityPrivateKey_withJavaSecurityPrivateKey_withJavaSecurityPublicKey_(self, staticPrivateKey, ephemeralPrivateKey, nil);
}

LibOrgBouncycastleJceSpecMQVPrivateKeySpec *new_LibOrgBouncycastleJceSpecMQVPrivateKeySpec_initWithJavaSecurityPrivateKey_withJavaSecurityPrivateKey_(id<JavaSecurityPrivateKey> staticPrivateKey, id<JavaSecurityPrivateKey> ephemeralPrivateKey) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJceSpecMQVPrivateKeySpec, initWithJavaSecurityPrivateKey_withJavaSecurityPrivateKey_, staticPrivateKey, ephemeralPrivateKey)
}

LibOrgBouncycastleJceSpecMQVPrivateKeySpec *create_LibOrgBouncycastleJceSpecMQVPrivateKeySpec_initWithJavaSecurityPrivateKey_withJavaSecurityPrivateKey_(id<JavaSecurityPrivateKey> staticPrivateKey, id<JavaSecurityPrivateKey> ephemeralPrivateKey) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJceSpecMQVPrivateKeySpec, initWithJavaSecurityPrivateKey_withJavaSecurityPrivateKey_, staticPrivateKey, ephemeralPrivateKey)
}

void LibOrgBouncycastleJceSpecMQVPrivateKeySpec_initWithJavaSecurityPrivateKey_withJavaSecurityPrivateKey_withJavaSecurityPublicKey_(LibOrgBouncycastleJceSpecMQVPrivateKeySpec *self, id<JavaSecurityPrivateKey> staticPrivateKey, id<JavaSecurityPrivateKey> ephemeralPrivateKey, id<JavaSecurityPublicKey> ephemeralPublicKey) {
  NSObject_init(self);
  self->staticPrivateKey_ = staticPrivateKey;
  self->ephemeralPrivateKey_ = ephemeralPrivateKey;
  self->ephemeralPublicKey_ = ephemeralPublicKey;
}

LibOrgBouncycastleJceSpecMQVPrivateKeySpec *new_LibOrgBouncycastleJceSpecMQVPrivateKeySpec_initWithJavaSecurityPrivateKey_withJavaSecurityPrivateKey_withJavaSecurityPublicKey_(id<JavaSecurityPrivateKey> staticPrivateKey, id<JavaSecurityPrivateKey> ephemeralPrivateKey, id<JavaSecurityPublicKey> ephemeralPublicKey) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJceSpecMQVPrivateKeySpec, initWithJavaSecurityPrivateKey_withJavaSecurityPrivateKey_withJavaSecurityPublicKey_, staticPrivateKey, ephemeralPrivateKey, ephemeralPublicKey)
}

LibOrgBouncycastleJceSpecMQVPrivateKeySpec *create_LibOrgBouncycastleJceSpecMQVPrivateKeySpec_initWithJavaSecurityPrivateKey_withJavaSecurityPrivateKey_withJavaSecurityPublicKey_(id<JavaSecurityPrivateKey> staticPrivateKey, id<JavaSecurityPrivateKey> ephemeralPrivateKey, id<JavaSecurityPublicKey> ephemeralPublicKey) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJceSpecMQVPrivateKeySpec, initWithJavaSecurityPrivateKey_withJavaSecurityPrivateKey_withJavaSecurityPublicKey_, staticPrivateKey, ephemeralPrivateKey, ephemeralPublicKey)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJceSpecMQVPrivateKeySpec)