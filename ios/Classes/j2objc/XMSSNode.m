//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/pqc/crypto/xmss/XMSSNode.java
//

#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "XMSSNode.h"
#include "XMSSUtil.h"

@interface LibOrgBouncycastlePqcCryptoXmssXMSSNode () {
 @public
  jint height_;
  IOSByteArray *value_;
}

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastlePqcCryptoXmssXMSSNode, value_, IOSByteArray *)

inline jlong LibOrgBouncycastlePqcCryptoXmssXMSSNode_get_serialVersionUID(void);
#define LibOrgBouncycastlePqcCryptoXmssXMSSNode_serialVersionUID 1LL
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastlePqcCryptoXmssXMSSNode, serialVersionUID, jlong)

@implementation LibOrgBouncycastlePqcCryptoXmssXMSSNode

- (instancetype)initWithInt:(jint)height
              withByteArray:(IOSByteArray *)value {
  LibOrgBouncycastlePqcCryptoXmssXMSSNode_initWithInt_withByteArray_(self, height, value);
  return self;
}

- (jint)getHeight {
  return height_;
}

- (IOSByteArray *)getValue {
  return LibOrgBouncycastlePqcCryptoXmssXMSSUtil_cloneArrayWithByteArray_(value_);
}

- (LibOrgBouncycastlePqcCryptoXmssXMSSNode *)java_clone {
  return new_LibOrgBouncycastlePqcCryptoXmssXMSSNode_initWithInt_withByteArray_([self getHeight], [self getValue]);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x4, -1, 0, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastlePqcCryptoXmssXMSSNode;", 0x4, 1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithInt:withByteArray:);
  methods[1].selector = @selector(getHeight);
  methods[2].selector = @selector(getValue);
  methods[3].selector = @selector(java_clone);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "serialVersionUID", "J", .constantValue.asLong = LibOrgBouncycastlePqcCryptoXmssXMSSNode_serialVersionUID, 0x1a, -1, -1, -1, -1 },
    { "height_", "I", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "value_", "[B", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "I[B", "clone" };
  static const J2ObjcClassInfo _LibOrgBouncycastlePqcCryptoXmssXMSSNode = { "XMSSNode", "lib.org.bouncycastle.pqc.crypto.xmss", ptrTable, methods, fields, 7, 0x11, 4, 3, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastlePqcCryptoXmssXMSSNode;
}

@end

void LibOrgBouncycastlePqcCryptoXmssXMSSNode_initWithInt_withByteArray_(LibOrgBouncycastlePqcCryptoXmssXMSSNode *self, jint height, IOSByteArray *value) {
  NSObject_init(self);
  self->height_ = height;
  self->value_ = value;
}

LibOrgBouncycastlePqcCryptoXmssXMSSNode *new_LibOrgBouncycastlePqcCryptoXmssXMSSNode_initWithInt_withByteArray_(jint height, IOSByteArray *value) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastlePqcCryptoXmssXMSSNode, initWithInt_withByteArray_, height, value)
}

LibOrgBouncycastlePqcCryptoXmssXMSSNode *create_LibOrgBouncycastlePqcCryptoXmssXMSSNode_initWithInt_withByteArray_(jint height, IOSByteArray *value) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastlePqcCryptoXmssXMSSNode, initWithInt_withByteArray_, height, value)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastlePqcCryptoXmssXMSSNode)
