//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/pqc/crypto/gmss/Treehash.java
//

#include "Digest.h"
#include "GMSSRandom.h"
#include "Hex.h"
#include "IOSObjectArray.h"
#include "IOSPrimitiveArray.h"
#include "Integers.h"
#include "J2ObjC_source.h"
#include "Treehash.h"
#include "java/io/PrintStream.h"
#include "java/lang/Integer.h"
#include "java/lang/Math.h"
#include "java/lang/System.h"
#include "java/util/Vector.h"

@interface LibOrgBouncycastlePqcCryptoGmssTreehash () {
 @public
  jint maxHeight_;
  JavaUtilVector *tailStack_;
  JavaUtilVector *heightOfNodes_;
  IOSByteArray *firstNode_;
  IOSByteArray *seedActive_;
  IOSByteArray *seedNext_;
  jint tailLength_;
  jint firstNodeHeight_;
  jboolean isInitialized_;
  jboolean isFinished_;
  jboolean seedInitialized_;
  id<LibOrgBouncycastleCryptoDigest> messDigestTree_;
}

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastlePqcCryptoGmssTreehash, tailStack_, JavaUtilVector *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastlePqcCryptoGmssTreehash, heightOfNodes_, JavaUtilVector *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastlePqcCryptoGmssTreehash, firstNode_, IOSByteArray *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastlePqcCryptoGmssTreehash, seedActive_, IOSByteArray *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastlePqcCryptoGmssTreehash, seedNext_, IOSByteArray *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastlePqcCryptoGmssTreehash, messDigestTree_, id<LibOrgBouncycastleCryptoDigest>)

@implementation LibOrgBouncycastlePqcCryptoGmssTreehash

- (instancetype)initWithLibOrgBouncycastleCryptoDigest:(id<LibOrgBouncycastleCryptoDigest>)name
                                        withByteArray2:(IOSObjectArray *)statByte
                                          withIntArray:(IOSIntArray *)statInt {
  LibOrgBouncycastlePqcCryptoGmssTreehash_initWithLibOrgBouncycastleCryptoDigest_withByteArray2_withIntArray_(self, name, statByte, statInt);
  return self;
}

- (instancetype)initWithJavaUtilVector:(JavaUtilVector *)tailStack
                               withInt:(jint)maxHeight
    withLibOrgBouncycastleCryptoDigest:(id<LibOrgBouncycastleCryptoDigest>)digest {
  LibOrgBouncycastlePqcCryptoGmssTreehash_initWithJavaUtilVector_withInt_withLibOrgBouncycastleCryptoDigest_(self, tailStack, maxHeight, digest);
  return self;
}

- (void)initializeSeedWithByteArray:(IOSByteArray *)seedIn {
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(seedIn, 0, self->seedNext_, 0, [((id<LibOrgBouncycastleCryptoDigest>) nil_chk(self->messDigestTree_)) getDigestSize]);
  self->seedInitialized_ = true;
}

- (void)initialize__ {
  if (!self->seedInitialized_) {
    [((JavaIoPrintStream *) nil_chk(JreLoadStatic(JavaLangSystem, err))) printlnWithNSString:JreStrcat("$I$", @"Seed ", self->maxHeight_, @" not initialized")];
    return;
  }
  self->heightOfNodes_ = new_JavaUtilVector_init();
  self->tailLength_ = 0;
  self->firstNode_ = nil;
  self->firstNodeHeight_ = -1;
  self->isInitialized_ = true;
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(self->seedNext_, 0, self->seedActive_, 0, [((id<LibOrgBouncycastleCryptoDigest>) nil_chk(messDigestTree_)) getDigestSize]);
}

- (void)updateWithLibOrgBouncycastlePqcCryptoGmssUtilGMSSRandom:(LibOrgBouncycastlePqcCryptoGmssUtilGMSSRandom *)gmssRandom
                                                  withByteArray:(IOSByteArray *)leaf {
  if (self->isFinished_) {
    [((JavaIoPrintStream *) nil_chk(JreLoadStatic(JavaLangSystem, err))) printlnWithNSString:@"No more update possible for treehash instance!"];
    return;
  }
  if (!self->isInitialized_) {
    [((JavaIoPrintStream *) nil_chk(JreLoadStatic(JavaLangSystem, err))) printlnWithNSString:@"Treehash instance not initialized before update"];
    return;
  }
  IOSByteArray *help = [IOSByteArray newArrayWithLength:[((id<LibOrgBouncycastleCryptoDigest>) nil_chk(self->messDigestTree_)) getDigestSize]];
  jint helpHeight = -1;
  (void) [((LibOrgBouncycastlePqcCryptoGmssUtilGMSSRandom *) nil_chk(gmssRandom)) nextSeedWithByteArray:self->seedActive_];
  if (self->firstNode_ == nil) {
    self->firstNode_ = leaf;
    self->firstNodeHeight_ = 0;
  }
  else {
    help = leaf;
    helpHeight = 0;
    while (self->tailLength_ > 0 && helpHeight == [((JavaLangInteger *) nil_chk(((JavaLangInteger *) cast_chk([((JavaUtilVector *) nil_chk(heightOfNodes_)) lastElement], [JavaLangInteger class])))) intValue]) {
      IOSByteArray *toBeHashed = [IOSByteArray newArrayWithLength:JreLShift32([((id<LibOrgBouncycastleCryptoDigest>) nil_chk(self->messDigestTree_)) getDigestSize], 1)];
      JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_([((JavaUtilVector *) nil_chk(self->tailStack_)) lastElement], 0, toBeHashed, 0, [((id<LibOrgBouncycastleCryptoDigest>) nil_chk(self->messDigestTree_)) getDigestSize]);
      [((JavaUtilVector *) nil_chk(self->tailStack_)) removeElementAtWithInt:[self->tailStack_ size] - 1];
      [((JavaUtilVector *) nil_chk(self->heightOfNodes_)) removeElementAtWithInt:[self->heightOfNodes_ size] - 1];
      JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(help, 0, toBeHashed, [((id<LibOrgBouncycastleCryptoDigest>) nil_chk(self->messDigestTree_)) getDigestSize], [((id<LibOrgBouncycastleCryptoDigest>) nil_chk(self->messDigestTree_)) getDigestSize]);
      [((id<LibOrgBouncycastleCryptoDigest>) nil_chk(messDigestTree_)) updateWithByteArray:toBeHashed withInt:0 withInt:toBeHashed->size_];
      help = [IOSByteArray newArrayWithLength:[((id<LibOrgBouncycastleCryptoDigest>) nil_chk(messDigestTree_)) getDigestSize]];
      [((id<LibOrgBouncycastleCryptoDigest>) nil_chk(messDigestTree_)) doFinalWithByteArray:help withInt:0];
      helpHeight++;
      self->tailLength_--;
    }
    [((JavaUtilVector *) nil_chk(self->tailStack_)) addElementWithId:help];
    [((JavaUtilVector *) nil_chk(self->heightOfNodes_)) addElementWithId:LibOrgBouncycastleUtilIntegers_valueOfWithInt_(helpHeight)];
    self->tailLength_++;
    if ([((JavaLangInteger *) nil_chk(((JavaLangInteger *) cast_chk([((JavaUtilVector *) nil_chk(heightOfNodes_)) lastElement], [JavaLangInteger class])))) intValue] == self->firstNodeHeight_) {
      IOSByteArray *toBeHashed = [IOSByteArray newArrayWithLength:JreLShift32([((id<LibOrgBouncycastleCryptoDigest>) nil_chk(self->messDigestTree_)) getDigestSize], 1)];
      JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(self->firstNode_, 0, toBeHashed, 0, [((id<LibOrgBouncycastleCryptoDigest>) nil_chk(self->messDigestTree_)) getDigestSize]);
      JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_([((JavaUtilVector *) nil_chk(self->tailStack_)) lastElement], 0, toBeHashed, [((id<LibOrgBouncycastleCryptoDigest>) nil_chk(self->messDigestTree_)) getDigestSize], [((id<LibOrgBouncycastleCryptoDigest>) nil_chk(self->messDigestTree_)) getDigestSize]);
      [((JavaUtilVector *) nil_chk(self->tailStack_)) removeElementAtWithInt:[self->tailStack_ size] - 1];
      [((JavaUtilVector *) nil_chk(self->heightOfNodes_)) removeElementAtWithInt:[self->heightOfNodes_ size] - 1];
      [((id<LibOrgBouncycastleCryptoDigest>) nil_chk(messDigestTree_)) updateWithByteArray:toBeHashed withInt:0 withInt:toBeHashed->size_];
      self->firstNode_ = [IOSByteArray newArrayWithLength:[((id<LibOrgBouncycastleCryptoDigest>) nil_chk(messDigestTree_)) getDigestSize]];
      [((id<LibOrgBouncycastleCryptoDigest>) nil_chk(messDigestTree_)) doFinalWithByteArray:self->firstNode_ withInt:0];
      self->firstNodeHeight_++;
      self->tailLength_ = 0;
    }
  }
  if (self->firstNodeHeight_ == self->maxHeight_) {
    self->isFinished_ = true;
  }
}

- (void)destroy {
  self->isInitialized_ = false;
  self->isFinished_ = false;
  self->firstNode_ = nil;
  self->tailLength_ = 0;
  self->firstNodeHeight_ = -1;
}

- (jint)getLowestNodeHeight {
  if (self->firstNode_ == nil) {
    return self->maxHeight_;
  }
  else if (self->tailLength_ == 0) {
    return self->firstNodeHeight_;
  }
  else {
    return JavaLangMath_minWithInt_withInt_(self->firstNodeHeight_, [((JavaLangInteger *) nil_chk(((JavaLangInteger *) cast_chk([((JavaUtilVector *) nil_chk(heightOfNodes_)) lastElement], [JavaLangInteger class])))) intValue]);
  }
}

- (jint)getFirstNodeHeight {
  if (firstNode_ == nil) {
    return maxHeight_;
  }
  return firstNodeHeight_;
}

- (jboolean)wasInitialized {
  return self->isInitialized_;
}

- (jboolean)wasFinished {
  return self->isFinished_;
}

- (IOSByteArray *)getFirstNode {
  return self->firstNode_;
}

- (IOSByteArray *)getSeedActive {
  return self->seedActive_;
}

- (void)setFirstNodeWithByteArray:(IOSByteArray *)hash_ {
  if (!self->isInitialized_) {
    [self initialize__];
  }
  self->firstNode_ = hash_;
  self->firstNodeHeight_ = self->maxHeight_;
  self->isFinished_ = true;
}

- (void)updateNextSeedWithLibOrgBouncycastlePqcCryptoGmssUtilGMSSRandom:(LibOrgBouncycastlePqcCryptoGmssUtilGMSSRandom *)gmssRandom {
  (void) [((LibOrgBouncycastlePqcCryptoGmssUtilGMSSRandom *) nil_chk(gmssRandom)) nextSeedWithByteArray:seedNext_];
}

- (JavaUtilVector *)getTailStack {
  return self->tailStack_;
}

- (IOSObjectArray *)getStatByte {
  IOSObjectArray *statByte = [IOSByteArray newArrayWithDimensions:2 lengths:(jint[]){ 3 + tailLength_, [((id<LibOrgBouncycastleCryptoDigest>) nil_chk(self->messDigestTree_)) getDigestSize] }];
  (void) IOSObjectArray_Set(statByte, 0, firstNode_);
  (void) IOSObjectArray_Set(statByte, 1, seedActive_);
  (void) IOSObjectArray_Set(statByte, 2, seedNext_);
  for (jint i = 0; i < tailLength_; i++) {
    (void) IOSObjectArray_Set(statByte, 3 + i, (IOSByteArray *) cast_chk([((JavaUtilVector *) nil_chk(tailStack_)) elementAtWithInt:i], [IOSByteArray class]));
  }
  return statByte;
}

- (IOSIntArray *)getStatInt {
  IOSIntArray *statInt = [IOSIntArray newArrayWithLength:6 + tailLength_];
  *IOSIntArray_GetRef(statInt, 0) = maxHeight_;
  *IOSIntArray_GetRef(statInt, 1) = tailLength_;
  *IOSIntArray_GetRef(statInt, 2) = firstNodeHeight_;
  if (self->isFinished_) {
    *IOSIntArray_GetRef(statInt, 3) = 1;
  }
  else {
    *IOSIntArray_GetRef(statInt, 3) = 0;
  }
  if (self->isInitialized_) {
    *IOSIntArray_GetRef(statInt, 4) = 1;
  }
  else {
    *IOSIntArray_GetRef(statInt, 4) = 0;
  }
  if (self->seedInitialized_) {
    *IOSIntArray_GetRef(statInt, 5) = 1;
  }
  else {
    *IOSIntArray_GetRef(statInt, 5) = 0;
  }
  for (jint i = 0; i < tailLength_; i++) {
    *IOSIntArray_GetRef(statInt, 6 + i) = [((JavaLangInteger *) nil_chk(((JavaLangInteger *) cast_chk([((JavaUtilVector *) nil_chk(heightOfNodes_)) elementAtWithInt:i], [JavaLangInteger class])))) intValue];
  }
  return statInt;
}

- (NSString *)description {
  NSString *out = @"Treehash    : ";
  for (jint i = 0; i < 6 + tailLength_; i++) {
    out = JreStrcat("$IC", out, IOSIntArray_Get(nil_chk([self getStatInt]), i), ' ');
  }
  for (jint i = 0; i < 3 + tailLength_; i++) {
    if (IOSObjectArray_Get(nil_chk([self getStatByte]), i) != nil) {
      out = JreStrcat("$$C", out, [NSString java_stringWithBytes:LibOrgBouncycastleUtilEncodersHex_encodeWithByteArray_((IOSObjectArray_Get(nil_chk([self getStatByte]), i)))], ' ');
    }
    else {
      out = JreStrcat("$$", out, @"null ");
    }
  }
  out = JreStrcat("$$I", out, @"  ", [((id<LibOrgBouncycastleCryptoDigest>) nil_chk(self->messDigestTree_)) getDigestSize]);
  return out;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 2, 3, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 4, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 5, 6, -1, -1, -1, -1 },
    { NULL, "V", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 7, 3, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 8, 9, -1, -1, -1, -1 },
    { NULL, "LJavaUtilVector;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[[B", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x1, 10, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleCryptoDigest:withByteArray2:withIntArray:);
  methods[1].selector = @selector(initWithJavaUtilVector:withInt:withLibOrgBouncycastleCryptoDigest:);
  methods[2].selector = @selector(initializeSeedWithByteArray:);
  methods[3].selector = @selector(initialize__);
  methods[4].selector = @selector(updateWithLibOrgBouncycastlePqcCryptoGmssUtilGMSSRandom:withByteArray:);
  methods[5].selector = @selector(destroy);
  methods[6].selector = @selector(getLowestNodeHeight);
  methods[7].selector = @selector(getFirstNodeHeight);
  methods[8].selector = @selector(wasInitialized);
  methods[9].selector = @selector(wasFinished);
  methods[10].selector = @selector(getFirstNode);
  methods[11].selector = @selector(getSeedActive);
  methods[12].selector = @selector(setFirstNodeWithByteArray:);
  methods[13].selector = @selector(updateNextSeedWithLibOrgBouncycastlePqcCryptoGmssUtilGMSSRandom:);
  methods[14].selector = @selector(getTailStack);
  methods[15].selector = @selector(getStatByte);
  methods[16].selector = @selector(getStatInt);
  methods[17].selector = @selector(description);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "maxHeight_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "tailStack_", "LJavaUtilVector;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "heightOfNodes_", "LJavaUtilVector;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "firstNode_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "seedActive_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "seedNext_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "tailLength_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "firstNodeHeight_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "isInitialized_", "Z", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "isFinished_", "Z", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "seedInitialized_", "Z", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "messDigestTree_", "LLibOrgBouncycastleCryptoDigest;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleCryptoDigest;[[B[I", "LJavaUtilVector;ILLibOrgBouncycastleCryptoDigest;", "initializeSeed", "[B", "initialize", "update", "LLibOrgBouncycastlePqcCryptoGmssUtilGMSSRandom;[B", "setFirstNode", "updateNextSeed", "LLibOrgBouncycastlePqcCryptoGmssUtilGMSSRandom;", "toString" };
  static const J2ObjcClassInfo _LibOrgBouncycastlePqcCryptoGmssTreehash = { "Treehash", "lib.org.bouncycastle.pqc.crypto.gmss", ptrTable, methods, fields, 7, 0x1, 18, 12, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastlePqcCryptoGmssTreehash;
}

@end

void LibOrgBouncycastlePqcCryptoGmssTreehash_initWithLibOrgBouncycastleCryptoDigest_withByteArray2_withIntArray_(LibOrgBouncycastlePqcCryptoGmssTreehash *self, id<LibOrgBouncycastleCryptoDigest> name, IOSObjectArray *statByte, IOSIntArray *statInt) {
  NSObject_init(self);
  self->messDigestTree_ = name;
  self->maxHeight_ = IOSIntArray_Get(nil_chk(statInt), 0);
  self->tailLength_ = IOSIntArray_Get(statInt, 1);
  self->firstNodeHeight_ = IOSIntArray_Get(statInt, 2);
  if (IOSIntArray_Get(statInt, 3) == 1) {
    self->isFinished_ = true;
  }
  else {
    self->isFinished_ = false;
  }
  if (IOSIntArray_Get(statInt, 4) == 1) {
    self->isInitialized_ = true;
  }
  else {
    self->isInitialized_ = false;
  }
  if (IOSIntArray_Get(statInt, 5) == 1) {
    self->seedInitialized_ = true;
  }
  else {
    self->seedInitialized_ = false;
  }
  self->heightOfNodes_ = new_JavaUtilVector_init();
  for (jint i = 0; i < self->tailLength_; i++) {
    [((JavaUtilVector *) nil_chk(self->heightOfNodes_)) addElementWithId:LibOrgBouncycastleUtilIntegers_valueOfWithInt_(IOSIntArray_Get(statInt, 6 + i))];
  }
  self->firstNode_ = IOSObjectArray_Get(nil_chk(statByte), 0);
  self->seedActive_ = IOSObjectArray_Get(statByte, 1);
  self->seedNext_ = IOSObjectArray_Get(statByte, 2);
  self->tailStack_ = new_JavaUtilVector_init();
  for (jint i = 0; i < self->tailLength_; i++) {
    [((JavaUtilVector *) nil_chk(self->tailStack_)) addElementWithId:IOSObjectArray_Get(statByte, 3 + i)];
  }
}

LibOrgBouncycastlePqcCryptoGmssTreehash *new_LibOrgBouncycastlePqcCryptoGmssTreehash_initWithLibOrgBouncycastleCryptoDigest_withByteArray2_withIntArray_(id<LibOrgBouncycastleCryptoDigest> name, IOSObjectArray *statByte, IOSIntArray *statInt) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastlePqcCryptoGmssTreehash, initWithLibOrgBouncycastleCryptoDigest_withByteArray2_withIntArray_, name, statByte, statInt)
}

LibOrgBouncycastlePqcCryptoGmssTreehash *create_LibOrgBouncycastlePqcCryptoGmssTreehash_initWithLibOrgBouncycastleCryptoDigest_withByteArray2_withIntArray_(id<LibOrgBouncycastleCryptoDigest> name, IOSObjectArray *statByte, IOSIntArray *statInt) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastlePqcCryptoGmssTreehash, initWithLibOrgBouncycastleCryptoDigest_withByteArray2_withIntArray_, name, statByte, statInt)
}

void LibOrgBouncycastlePqcCryptoGmssTreehash_initWithJavaUtilVector_withInt_withLibOrgBouncycastleCryptoDigest_(LibOrgBouncycastlePqcCryptoGmssTreehash *self, JavaUtilVector *tailStack, jint maxHeight, id<LibOrgBouncycastleCryptoDigest> digest) {
  NSObject_init(self);
  self->tailStack_ = tailStack;
  self->maxHeight_ = maxHeight;
  self->firstNode_ = nil;
  self->isInitialized_ = false;
  self->isFinished_ = false;
  self->seedInitialized_ = false;
  self->messDigestTree_ = digest;
  self->seedNext_ = [IOSByteArray newArrayWithLength:[((id<LibOrgBouncycastleCryptoDigest>) nil_chk(self->messDigestTree_)) getDigestSize]];
  self->seedActive_ = [IOSByteArray newArrayWithLength:[((id<LibOrgBouncycastleCryptoDigest>) nil_chk(self->messDigestTree_)) getDigestSize]];
}

LibOrgBouncycastlePqcCryptoGmssTreehash *new_LibOrgBouncycastlePqcCryptoGmssTreehash_initWithJavaUtilVector_withInt_withLibOrgBouncycastleCryptoDigest_(JavaUtilVector *tailStack, jint maxHeight, id<LibOrgBouncycastleCryptoDigest> digest) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastlePqcCryptoGmssTreehash, initWithJavaUtilVector_withInt_withLibOrgBouncycastleCryptoDigest_, tailStack, maxHeight, digest)
}

LibOrgBouncycastlePqcCryptoGmssTreehash *create_LibOrgBouncycastlePqcCryptoGmssTreehash_initWithJavaUtilVector_withInt_withLibOrgBouncycastleCryptoDigest_(JavaUtilVector *tailStack, jint maxHeight, id<LibOrgBouncycastleCryptoDigest> digest) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastlePqcCryptoGmssTreehash, initWithJavaUtilVector_withInt_withLibOrgBouncycastleCryptoDigest_, tailStack, maxHeight, digest)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastlePqcCryptoGmssTreehash)
