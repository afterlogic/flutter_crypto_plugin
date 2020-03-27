//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/digests/NonMemoableDigest.java
//

#include "ExtendedDigest.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "NonMemoableDigest.h"
#include "java/lang/IllegalArgumentException.h"

@interface LibOrgBouncycastleCryptoDigestsNonMemoableDigest () {
 @public
  id<LibOrgBouncycastleCryptoExtendedDigest> baseDigest_;
}

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoDigestsNonMemoableDigest, baseDigest_, id<LibOrgBouncycastleCryptoExtendedDigest>)

@implementation LibOrgBouncycastleCryptoDigestsNonMemoableDigest

- (instancetype)initWithLibOrgBouncycastleCryptoExtendedDigest:(id<LibOrgBouncycastleCryptoExtendedDigest>)baseDigest {
  LibOrgBouncycastleCryptoDigestsNonMemoableDigest_initWithLibOrgBouncycastleCryptoExtendedDigest_(self, baseDigest);
  return self;
}

- (NSString *)getAlgorithmName {
  return [((id<LibOrgBouncycastleCryptoExtendedDigest>) nil_chk(baseDigest_)) getAlgorithmName];
}

- (jint)getDigestSize {
  return [((id<LibOrgBouncycastleCryptoExtendedDigest>) nil_chk(baseDigest_)) getDigestSize];
}

- (void)updateWithByte:(jbyte)inArg {
  [((id<LibOrgBouncycastleCryptoExtendedDigest>) nil_chk(baseDigest_)) updateWithByte:inArg];
}

- (void)updateWithByteArray:(IOSByteArray *)inArg
                    withInt:(jint)inOff
                    withInt:(jint)len {
  [((id<LibOrgBouncycastleCryptoExtendedDigest>) nil_chk(baseDigest_)) updateWithByteArray:inArg withInt:inOff withInt:len];
}

- (jint)doFinalWithByteArray:(IOSByteArray *)outArg
                     withInt:(jint)outOff {
  return [((id<LibOrgBouncycastleCryptoExtendedDigest>) nil_chk(baseDigest_)) doFinalWithByteArray:outArg withInt:outOff];
}

- (void)reset {
  [((id<LibOrgBouncycastleCryptoExtendedDigest>) nil_chk(baseDigest_)) reset];
}

- (jint)getByteLength {
  return [((id<LibOrgBouncycastleCryptoExtendedDigest>) nil_chk(baseDigest_)) getByteLength];
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 1, 2, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 1, 3, -1, -1, -1, -1 },
    { NULL, "I", 0x1, 4, 5, -1, -1, -1, -1 },
    { NULL, "V", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleCryptoExtendedDigest:);
  methods[1].selector = @selector(getAlgorithmName);
  methods[2].selector = @selector(getDigestSize);
  methods[3].selector = @selector(updateWithByte:);
  methods[4].selector = @selector(updateWithByteArray:withInt:withInt:);
  methods[5].selector = @selector(doFinalWithByteArray:withInt:);
  methods[6].selector = @selector(reset);
  methods[7].selector = @selector(getByteLength);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "baseDigest_", "LLibOrgBouncycastleCryptoExtendedDigest;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleCryptoExtendedDigest;", "update", "B", "[BII", "doFinal", "[BI" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoDigestsNonMemoableDigest = { "NonMemoableDigest", "lib.org.bouncycastle.crypto.digests", ptrTable, methods, fields, 7, 0x1, 8, 1, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoDigestsNonMemoableDigest;
}

@end

void LibOrgBouncycastleCryptoDigestsNonMemoableDigest_initWithLibOrgBouncycastleCryptoExtendedDigest_(LibOrgBouncycastleCryptoDigestsNonMemoableDigest *self, id<LibOrgBouncycastleCryptoExtendedDigest> baseDigest) {
  NSObject_init(self);
  if (baseDigest == nil) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"baseDigest must not be null");
  }
  self->baseDigest_ = baseDigest;
}

LibOrgBouncycastleCryptoDigestsNonMemoableDigest *new_LibOrgBouncycastleCryptoDigestsNonMemoableDigest_initWithLibOrgBouncycastleCryptoExtendedDigest_(id<LibOrgBouncycastleCryptoExtendedDigest> baseDigest) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoDigestsNonMemoableDigest, initWithLibOrgBouncycastleCryptoExtendedDigest_, baseDigest)
}

LibOrgBouncycastleCryptoDigestsNonMemoableDigest *create_LibOrgBouncycastleCryptoDigestsNonMemoableDigest_initWithLibOrgBouncycastleCryptoExtendedDigest_(id<LibOrgBouncycastleCryptoExtendedDigest> baseDigest) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoDigestsNonMemoableDigest, initWithLibOrgBouncycastleCryptoExtendedDigest_, baseDigest)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoDigestsNonMemoableDigest)