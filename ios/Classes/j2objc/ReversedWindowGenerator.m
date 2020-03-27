//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/prng/ReversedWindowGenerator.java
//

#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "RandomGenerator.h"
#include "ReversedWindowGenerator.h"
#include "java/lang/IllegalArgumentException.h"

@interface LibOrgBouncycastleCryptoPrngReversedWindowGenerator () {
 @public
  id<LibOrgBouncycastleCryptoPrngRandomGenerator> generator_;
  IOSByteArray *window_;
  jint windowCount_;
}

- (void)doNextBytesWithByteArray:(IOSByteArray *)bytes
                         withInt:(jint)start
                         withInt:(jint)len;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoPrngReversedWindowGenerator, generator_, id<LibOrgBouncycastleCryptoPrngRandomGenerator>)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoPrngReversedWindowGenerator, window_, IOSByteArray *)

__attribute__((unused)) static void LibOrgBouncycastleCryptoPrngReversedWindowGenerator_doNextBytesWithByteArray_withInt_withInt_(LibOrgBouncycastleCryptoPrngReversedWindowGenerator *self, IOSByteArray *bytes, jint start, jint len);

@implementation LibOrgBouncycastleCryptoPrngReversedWindowGenerator

- (instancetype)initWithLibOrgBouncycastleCryptoPrngRandomGenerator:(id<LibOrgBouncycastleCryptoPrngRandomGenerator>)generator
                                                            withInt:(jint)windowSize {
  LibOrgBouncycastleCryptoPrngReversedWindowGenerator_initWithLibOrgBouncycastleCryptoPrngRandomGenerator_withInt_(self, generator, windowSize);
  return self;
}

- (void)addSeedMaterialWithByteArray:(IOSByteArray *)seed {
  @synchronized(self) {
    windowCount_ = 0;
    [((id<LibOrgBouncycastleCryptoPrngRandomGenerator>) nil_chk(generator_)) addSeedMaterialWithByteArray:seed];
  }
}

- (void)addSeedMaterialWithLong:(jlong)seed {
  @synchronized(self) {
    windowCount_ = 0;
    [((id<LibOrgBouncycastleCryptoPrngRandomGenerator>) nil_chk(generator_)) addSeedMaterialWithLong:seed];
  }
}

- (void)nextBytesWithByteArray:(IOSByteArray *)bytes {
  LibOrgBouncycastleCryptoPrngReversedWindowGenerator_doNextBytesWithByteArray_withInt_withInt_(self, bytes, 0, ((IOSByteArray *) nil_chk(bytes))->size_);
}

- (void)nextBytesWithByteArray:(IOSByteArray *)bytes
                       withInt:(jint)start
                       withInt:(jint)len {
  LibOrgBouncycastleCryptoPrngReversedWindowGenerator_doNextBytesWithByteArray_withInt_withInt_(self, bytes, start, len);
}

- (void)doNextBytesWithByteArray:(IOSByteArray *)bytes
                         withInt:(jint)start
                         withInt:(jint)len {
  LibOrgBouncycastleCryptoPrngReversedWindowGenerator_doNextBytesWithByteArray_withInt_withInt_(self, bytes, start, len);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 1, 2, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 1, 3, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 4, 2, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 4, 5, -1, -1, -1, -1 },
    { NULL, "V", 0x2, 6, 5, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleCryptoPrngRandomGenerator:withInt:);
  methods[1].selector = @selector(addSeedMaterialWithByteArray:);
  methods[2].selector = @selector(addSeedMaterialWithLong:);
  methods[3].selector = @selector(nextBytesWithByteArray:);
  methods[4].selector = @selector(nextBytesWithByteArray:withInt:withInt:);
  methods[5].selector = @selector(doNextBytesWithByteArray:withInt:withInt:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "generator_", "LLibOrgBouncycastleCryptoPrngRandomGenerator;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "window_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "windowCount_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleCryptoPrngRandomGenerator;I", "addSeedMaterial", "[B", "J", "nextBytes", "[BII", "doNextBytes" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoPrngReversedWindowGenerator = { "ReversedWindowGenerator", "lib.org.bouncycastle.crypto.prng", ptrTable, methods, fields, 7, 0x1, 6, 3, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoPrngReversedWindowGenerator;
}

@end

void LibOrgBouncycastleCryptoPrngReversedWindowGenerator_initWithLibOrgBouncycastleCryptoPrngRandomGenerator_withInt_(LibOrgBouncycastleCryptoPrngReversedWindowGenerator *self, id<LibOrgBouncycastleCryptoPrngRandomGenerator> generator, jint windowSize) {
  NSObject_init(self);
  if (generator == nil) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"generator cannot be null");
  }
  if (windowSize < 2) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"windowSize must be at least 2");
  }
  self->generator_ = generator;
  self->window_ = [IOSByteArray newArrayWithLength:windowSize];
}

LibOrgBouncycastleCryptoPrngReversedWindowGenerator *new_LibOrgBouncycastleCryptoPrngReversedWindowGenerator_initWithLibOrgBouncycastleCryptoPrngRandomGenerator_withInt_(id<LibOrgBouncycastleCryptoPrngRandomGenerator> generator, jint windowSize) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoPrngReversedWindowGenerator, initWithLibOrgBouncycastleCryptoPrngRandomGenerator_withInt_, generator, windowSize)
}

LibOrgBouncycastleCryptoPrngReversedWindowGenerator *create_LibOrgBouncycastleCryptoPrngReversedWindowGenerator_initWithLibOrgBouncycastleCryptoPrngRandomGenerator_withInt_(id<LibOrgBouncycastleCryptoPrngRandomGenerator> generator, jint windowSize) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoPrngReversedWindowGenerator, initWithLibOrgBouncycastleCryptoPrngRandomGenerator_withInt_, generator, windowSize)
}

void LibOrgBouncycastleCryptoPrngReversedWindowGenerator_doNextBytesWithByteArray_withInt_withInt_(LibOrgBouncycastleCryptoPrngReversedWindowGenerator *self, IOSByteArray *bytes, jint start, jint len) {
  @synchronized(self) {
    jint done = 0;
    while (done < len) {
      if (self->windowCount_ < 1) {
        [((id<LibOrgBouncycastleCryptoPrngRandomGenerator>) nil_chk(self->generator_)) nextBytesWithByteArray:self->window_ withInt:0 withInt:((IOSByteArray *) nil_chk(self->window_))->size_];
        self->windowCount_ = ((IOSByteArray *) nil_chk(self->window_))->size_;
      }
      *IOSByteArray_GetRef(nil_chk(bytes), start + done++) = IOSByteArray_Get(nil_chk(self->window_), --self->windowCount_);
    }
  }
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoPrngReversedWindowGenerator)
