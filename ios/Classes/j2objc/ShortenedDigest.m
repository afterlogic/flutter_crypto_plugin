//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/digests/ShortenedDigest.java
//

#include "ExtendedDigest.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "ShortenedDigest.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/lang/System.h"

@interface LibOrgBouncycastleCryptoDigestsShortenedDigest () {
 @public
  id<LibOrgBouncycastleCryptoExtendedDigest> baseDigest_;
  jint length_;
}

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoDigestsShortenedDigest, baseDigest_, id<LibOrgBouncycastleCryptoExtendedDigest>)

@implementation LibOrgBouncycastleCryptoDigestsShortenedDigest

- (instancetype)initWithLibOrgBouncycastleCryptoExtendedDigest:(id<LibOrgBouncycastleCryptoExtendedDigest>)baseDigest
                                                       withInt:(jint)length {
  LibOrgBouncycastleCryptoDigestsShortenedDigest_initWithLibOrgBouncycastleCryptoExtendedDigest_withInt_(self, baseDigest, length);
  return self;
}

- (NSString *)getAlgorithmName {
  return JreStrcat("$CIC", [((id<LibOrgBouncycastleCryptoExtendedDigest>) nil_chk(baseDigest_)) getAlgorithmName], '(', length_ * 8, ')');
}

- (jint)getDigestSize {
  return length_;
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
  IOSByteArray *tmp = [IOSByteArray newArrayWithLength:[((id<LibOrgBouncycastleCryptoExtendedDigest>) nil_chk(baseDigest_)) getDigestSize]];
  [((id<LibOrgBouncycastleCryptoExtendedDigest>) nil_chk(baseDigest_)) doFinalWithByteArray:tmp withInt:0];
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(tmp, 0, outArg, outOff, length_);
  return length_;
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
  methods[0].selector = @selector(initWithLibOrgBouncycastleCryptoExtendedDigest:withInt:);
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
    { "length_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleCryptoExtendedDigest;I", "update", "B", "[BII", "doFinal", "[BI" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoDigestsShortenedDigest = { "ShortenedDigest", "lib.org.bouncycastle.crypto.digests", ptrTable, methods, fields, 7, 0x1, 8, 2, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoDigestsShortenedDigest;
}

@end

void LibOrgBouncycastleCryptoDigestsShortenedDigest_initWithLibOrgBouncycastleCryptoExtendedDigest_withInt_(LibOrgBouncycastleCryptoDigestsShortenedDigest *self, id<LibOrgBouncycastleCryptoExtendedDigest> baseDigest, jint length) {
  NSObject_init(self);
  if (baseDigest == nil) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"baseDigest must not be null");
  }
  if (length > [baseDigest getDigestSize]) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"baseDigest output not large enough to support length");
  }
  self->baseDigest_ = baseDigest;
  self->length_ = length;
}

LibOrgBouncycastleCryptoDigestsShortenedDigest *new_LibOrgBouncycastleCryptoDigestsShortenedDigest_initWithLibOrgBouncycastleCryptoExtendedDigest_withInt_(id<LibOrgBouncycastleCryptoExtendedDigest> baseDigest, jint length) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoDigestsShortenedDigest, initWithLibOrgBouncycastleCryptoExtendedDigest_withInt_, baseDigest, length)
}

LibOrgBouncycastleCryptoDigestsShortenedDigest *create_LibOrgBouncycastleCryptoDigestsShortenedDigest_initWithLibOrgBouncycastleCryptoExtendedDigest_withInt_(id<LibOrgBouncycastleCryptoExtendedDigest> baseDigest, jint length) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoDigestsShortenedDigest, initWithLibOrgBouncycastleCryptoExtendedDigest_withInt_, baseDigest, length)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoDigestsShortenedDigest)
