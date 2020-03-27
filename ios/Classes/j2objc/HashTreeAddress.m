//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/pqc/crypto/xmss/HashTreeAddress.java
//

#include "HashTreeAddress.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "Pack.h"
#include "XMSSAddress.h"

#pragma clang diagnostic ignored "-Wincomplete-implementation"

@interface LibOrgBouncycastlePqcCryptoXmssHashTreeAddress () {
 @public
  jint padding_;
  jint treeHeight_;
  jint treeIndex_;
}

- (instancetype)initWithLibOrgBouncycastlePqcCryptoXmssHashTreeAddress_Builder:(LibOrgBouncycastlePqcCryptoXmssHashTreeAddress_Builder *)builder;

@end

inline jint LibOrgBouncycastlePqcCryptoXmssHashTreeAddress_get_TYPE(void);
#define LibOrgBouncycastlePqcCryptoXmssHashTreeAddress_TYPE 2
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastlePqcCryptoXmssHashTreeAddress, TYPE, jint)

inline jint LibOrgBouncycastlePqcCryptoXmssHashTreeAddress_get_PADDING(void);
#define LibOrgBouncycastlePqcCryptoXmssHashTreeAddress_PADDING 0
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastlePqcCryptoXmssHashTreeAddress, PADDING, jint)

__attribute__((unused)) static void LibOrgBouncycastlePqcCryptoXmssHashTreeAddress_initWithLibOrgBouncycastlePqcCryptoXmssHashTreeAddress_Builder_(LibOrgBouncycastlePqcCryptoXmssHashTreeAddress *self, LibOrgBouncycastlePqcCryptoXmssHashTreeAddress_Builder *builder);

__attribute__((unused)) static LibOrgBouncycastlePqcCryptoXmssHashTreeAddress *new_LibOrgBouncycastlePqcCryptoXmssHashTreeAddress_initWithLibOrgBouncycastlePqcCryptoXmssHashTreeAddress_Builder_(LibOrgBouncycastlePqcCryptoXmssHashTreeAddress_Builder *builder) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastlePqcCryptoXmssHashTreeAddress *create_LibOrgBouncycastlePqcCryptoXmssHashTreeAddress_initWithLibOrgBouncycastlePqcCryptoXmssHashTreeAddress_Builder_(LibOrgBouncycastlePqcCryptoXmssHashTreeAddress_Builder *builder);

@interface LibOrgBouncycastlePqcCryptoXmssHashTreeAddress_Builder () {
 @public
  jint treeHeight_;
  jint treeIndex_;
}

@end

@implementation LibOrgBouncycastlePqcCryptoXmssHashTreeAddress

- (instancetype)initWithLibOrgBouncycastlePqcCryptoXmssHashTreeAddress_Builder:(LibOrgBouncycastlePqcCryptoXmssHashTreeAddress_Builder *)builder {
  LibOrgBouncycastlePqcCryptoXmssHashTreeAddress_initWithLibOrgBouncycastlePqcCryptoXmssHashTreeAddress_Builder_(self, builder);
  return self;
}

- (IOSByteArray *)toByteArray {
  IOSByteArray *byteRepresentation = [super toByteArray];
  LibOrgBouncycastleUtilPack_intToBigEndianWithInt_withByteArray_withInt_(padding_, byteRepresentation, 16);
  LibOrgBouncycastleUtilPack_intToBigEndianWithInt_withByteArray_withInt_(treeHeight_, byteRepresentation, 20);
  LibOrgBouncycastleUtilPack_intToBigEndianWithInt_withByteArray_withInt_(treeIndex_, byteRepresentation, 24);
  return byteRepresentation;
}

- (jint)getPadding {
  return padding_;
}

- (jint)getTreeHeight {
  return treeHeight_;
}

- (jint)getTreeIndex {
  return treeIndex_;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x2, -1, 0, -1, -1, -1, -1 },
    { NULL, "[B", 0x4, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x4, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x4, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x4, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastlePqcCryptoXmssHashTreeAddress_Builder:);
  methods[1].selector = @selector(toByteArray);
  methods[2].selector = @selector(getPadding);
  methods[3].selector = @selector(getTreeHeight);
  methods[4].selector = @selector(getTreeIndex);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "TYPE", "I", .constantValue.asInt = LibOrgBouncycastlePqcCryptoXmssHashTreeAddress_TYPE, 0x1a, -1, -1, -1, -1 },
    { "PADDING", "I", .constantValue.asInt = LibOrgBouncycastlePqcCryptoXmssHashTreeAddress_PADDING, 0x1a, -1, -1, -1, -1 },
    { "padding_", "I", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "treeHeight_", "I", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "treeIndex_", "I", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastlePqcCryptoXmssHashTreeAddress_Builder;" };
  static const J2ObjcClassInfo _LibOrgBouncycastlePqcCryptoXmssHashTreeAddress = { "HashTreeAddress", "lib.org.bouncycastle.pqc.crypto.xmss", ptrTable, methods, fields, 7, 0x10, 5, 5, -1, 0, -1, -1, -1 };
  return &_LibOrgBouncycastlePqcCryptoXmssHashTreeAddress;
}

@end

void LibOrgBouncycastlePqcCryptoXmssHashTreeAddress_initWithLibOrgBouncycastlePqcCryptoXmssHashTreeAddress_Builder_(LibOrgBouncycastlePqcCryptoXmssHashTreeAddress *self, LibOrgBouncycastlePqcCryptoXmssHashTreeAddress_Builder *builder) {
  LibOrgBouncycastlePqcCryptoXmssXMSSAddress_initWithLibOrgBouncycastlePqcCryptoXmssXMSSAddress_Builder_(self, builder);
  self->padding_ = LibOrgBouncycastlePqcCryptoXmssHashTreeAddress_PADDING;
  self->treeHeight_ = ((LibOrgBouncycastlePqcCryptoXmssHashTreeAddress_Builder *) nil_chk(builder))->treeHeight_;
  self->treeIndex_ = builder->treeIndex_;
}

LibOrgBouncycastlePqcCryptoXmssHashTreeAddress *new_LibOrgBouncycastlePqcCryptoXmssHashTreeAddress_initWithLibOrgBouncycastlePqcCryptoXmssHashTreeAddress_Builder_(LibOrgBouncycastlePqcCryptoXmssHashTreeAddress_Builder *builder) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastlePqcCryptoXmssHashTreeAddress, initWithLibOrgBouncycastlePqcCryptoXmssHashTreeAddress_Builder_, builder)
}

LibOrgBouncycastlePqcCryptoXmssHashTreeAddress *create_LibOrgBouncycastlePqcCryptoXmssHashTreeAddress_initWithLibOrgBouncycastlePqcCryptoXmssHashTreeAddress_Builder_(LibOrgBouncycastlePqcCryptoXmssHashTreeAddress_Builder *builder) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastlePqcCryptoXmssHashTreeAddress, initWithLibOrgBouncycastlePqcCryptoXmssHashTreeAddress_Builder_, builder)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastlePqcCryptoXmssHashTreeAddress)

@implementation LibOrgBouncycastlePqcCryptoXmssHashTreeAddress_Builder

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastlePqcCryptoXmssHashTreeAddress_Builder_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (LibOrgBouncycastlePqcCryptoXmssHashTreeAddress_Builder *)withTreeHeightWithInt:(jint)val {
  treeHeight_ = val;
  return self;
}

- (LibOrgBouncycastlePqcCryptoXmssHashTreeAddress_Builder *)withTreeIndexWithInt:(jint)val {
  treeIndex_ = val;
  return self;
}

- (LibOrgBouncycastlePqcCryptoXmssXMSSAddress *)build {
  return new_LibOrgBouncycastlePqcCryptoXmssHashTreeAddress_initWithLibOrgBouncycastlePqcCryptoXmssHashTreeAddress_Builder_(self);
}

- (LibOrgBouncycastlePqcCryptoXmssHashTreeAddress_Builder *)getThis {
  return self;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x4, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastlePqcCryptoXmssHashTreeAddress_Builder;", 0x4, 0, 1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastlePqcCryptoXmssHashTreeAddress_Builder;", 0x4, 2, 1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastlePqcCryptoXmssXMSSAddress;", 0x4, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastlePqcCryptoXmssHashTreeAddress_Builder;", 0x4, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(withTreeHeightWithInt:);
  methods[2].selector = @selector(withTreeIndexWithInt:);
  methods[3].selector = @selector(build);
  methods[4].selector = @selector(getThis);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "treeHeight_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "treeIndex_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "withTreeHeight", "I", "withTreeIndex", "LLibOrgBouncycastlePqcCryptoXmssHashTreeAddress;", "Llib/org/bouncycastle/pqc/crypto/xmss/XMSSAddress$Builder<Llib/org/bouncycastle/pqc/crypto/xmss/HashTreeAddress$Builder;>;" };
  static const J2ObjcClassInfo _LibOrgBouncycastlePqcCryptoXmssHashTreeAddress_Builder = { "Builder", "lib.org.bouncycastle.pqc.crypto.xmss", ptrTable, methods, fields, 7, 0xc, 5, 2, 3, -1, -1, 4, -1 };
  return &_LibOrgBouncycastlePqcCryptoXmssHashTreeAddress_Builder;
}

@end

void LibOrgBouncycastlePqcCryptoXmssHashTreeAddress_Builder_init(LibOrgBouncycastlePqcCryptoXmssHashTreeAddress_Builder *self) {
  LibOrgBouncycastlePqcCryptoXmssXMSSAddress_Builder_initWithInt_(self, LibOrgBouncycastlePqcCryptoXmssHashTreeAddress_TYPE);
  self->treeHeight_ = 0;
  self->treeIndex_ = 0;
}

LibOrgBouncycastlePqcCryptoXmssHashTreeAddress_Builder *new_LibOrgBouncycastlePqcCryptoXmssHashTreeAddress_Builder_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastlePqcCryptoXmssHashTreeAddress_Builder, init)
}

LibOrgBouncycastlePqcCryptoXmssHashTreeAddress_Builder *create_LibOrgBouncycastlePqcCryptoXmssHashTreeAddress_Builder_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastlePqcCryptoXmssHashTreeAddress_Builder, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastlePqcCryptoXmssHashTreeAddress_Builder)
