//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/util/test/UtilTestFixedSecureRandom.java
//

#include "Hex.h"
#include "IOSClass.h"
#include "IOSObjectArray.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "Pack.h"
#include "UtilTestFixedSecureRandom.h"
#include "java/io/ByteArrayOutputStream.h"
#include "java/io/IOException.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/lang/IllegalStateException.h"
#include "java/lang/System.h"
#include "java/math/BigInteger.h"
#include "java/security/Provider.h"
#include "java/security/SecureRandom.h"

@interface LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom () {
 @public
  IOSByteArray *_data_;
  jint _index_;
}

+ (IOSObjectArray *)buildDataArrayWithByteArray2:(IOSObjectArray *)values;

- (jint)nextValue;

+ (IOSByteArray *)expandToBitLengthWithInt:(jint)bitLength
                             withByteArray:(IOSByteArray *)v;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom, _data_, IOSByteArray *)

inline JavaMathBigInteger *LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_get_REGULAR(void);
inline JavaMathBigInteger *LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_set_REGULAR(JavaMathBigInteger *value);
static JavaMathBigInteger *LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_REGULAR;
J2OBJC_STATIC_FIELD_OBJ(LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom, REGULAR, JavaMathBigInteger *)

inline JavaMathBigInteger *LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_get_ANDROID(void);
inline JavaMathBigInteger *LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_set_ANDROID(JavaMathBigInteger *value);
static JavaMathBigInteger *LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_ANDROID;
J2OBJC_STATIC_FIELD_OBJ(LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom, ANDROID, JavaMathBigInteger *)

inline JavaMathBigInteger *LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_get_CLASSPATH(void);
inline JavaMathBigInteger *LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_set_CLASSPATH(JavaMathBigInteger *value);
static JavaMathBigInteger *LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_CLASSPATH;
J2OBJC_STATIC_FIELD_OBJ(LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom, CLASSPATH, JavaMathBigInteger *)

inline jboolean LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_get_isAndroidStyle(void);
static jboolean LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_isAndroidStyle;
J2OBJC_STATIC_FIELD_PRIMITIVE_FINAL(LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom, isAndroidStyle, jboolean)

inline jboolean LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_get_isClasspathStyle(void);
static jboolean LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_isClasspathStyle;
J2OBJC_STATIC_FIELD_PRIMITIVE_FINAL(LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom, isClasspathStyle, jboolean)

inline jboolean LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_get_isRegularStyle(void);
static jboolean LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_isRegularStyle;
J2OBJC_STATIC_FIELD_PRIMITIVE_FINAL(LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom, isRegularStyle, jboolean)

__attribute__((unused)) static IOSObjectArray *LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_buildDataArrayWithByteArray2_(IOSObjectArray *values);

__attribute__((unused)) static jint LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_nextValue(LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom *self);

__attribute__((unused)) static IOSByteArray *LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_expandToBitLengthWithInt_withByteArray_(jint bitLength, IOSByteArray *v);

@interface LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_RandomChecker : JavaSecuritySecureRandom {
 @public
  IOSByteArray *data_;
  jint index_;
}

- (instancetype)init;

- (void)nextBytesWithByteArray:(IOSByteArray *)bytes;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_RandomChecker)

J2OBJC_FIELD_SETTER(LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_RandomChecker, data_, IOSByteArray *)

__attribute__((unused)) static void LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_RandomChecker_init(LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_RandomChecker *self);

__attribute__((unused)) static LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_RandomChecker *new_LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_RandomChecker_init(void) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_RandomChecker *create_LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_RandomChecker_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_RandomChecker)

@interface LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_DummyProvider : JavaSecurityProvider

- (instancetype)init;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_DummyProvider)

__attribute__((unused)) static void LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_DummyProvider_init(LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_DummyProvider *self);

__attribute__((unused)) static LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_DummyProvider *new_LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_DummyProvider_init(void) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_DummyProvider *create_LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_DummyProvider_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_DummyProvider)

J2OBJC_INITIALIZED_DEFN(LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom)

@implementation LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom

- (instancetype)initWithByteArray:(IOSByteArray *)value {
  LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_initWithByteArray_(self, value);
  return self;
}

- (instancetype)initWithByteArray2:(IOSObjectArray *)values {
  LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_initWithByteArray2_(self, values);
  return self;
}

+ (IOSObjectArray *)buildDataArrayWithByteArray2:(IOSObjectArray *)values {
  return LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_buildDataArrayWithByteArray2_(values);
}

- (instancetype)initWithLibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_SourceArray:(IOSObjectArray *)sources {
  LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_initWithLibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_SourceArray_(self, sources);
  return self;
}

- (void)nextBytesWithByteArray:(IOSByteArray *)bytes {
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(_data_, _index_, bytes, 0, ((IOSByteArray *) nil_chk(bytes))->size_);
  _index_ += bytes->size_;
}

- (IOSByteArray *)generateSeedWithInt:(jint)numBytes {
  IOSByteArray *bytes = [IOSByteArray newArrayWithLength:numBytes];
  [self nextBytesWithByteArray:bytes];
  return bytes;
}

- (jint)nextInt {
  jint val = 0;
  val |= JreLShift32(LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_nextValue(self), 24);
  val |= JreLShift32(LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_nextValue(self), 16);
  val |= JreLShift32(LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_nextValue(self), 8);
  val |= LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_nextValue(self);
  return val;
}

- (jlong)nextLong {
  jlong val = 0;
  val |= JreLShift64((jlong) LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_nextValue(self), 56);
  val |= JreLShift64((jlong) LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_nextValue(self), 48);
  val |= JreLShift64((jlong) LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_nextValue(self), 40);
  val |= JreLShift64((jlong) LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_nextValue(self), 32);
  val |= JreLShift64((jlong) LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_nextValue(self), 24);
  val |= JreLShift64((jlong) LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_nextValue(self), 16);
  val |= JreLShift64((jlong) LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_nextValue(self), 8);
  val |= (jlong) LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_nextValue(self);
  return val;
}

- (jboolean)isExhausted {
  return _index_ == ((IOSByteArray *) nil_chk(_data_))->size_;
}

- (jint)nextValue {
  return LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_nextValue(self);
}

+ (IOSByteArray *)expandToBitLengthWithInt:(jint)bitLength
                             withByteArray:(IOSByteArray *)v {
  return LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_expandToBitLengthWithInt_withByteArray_(bitLength, v);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 1, -1, -1, -1, -1 },
    { NULL, "[LLibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_Data;", 0xa, 2, 1, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 3, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 4, 0, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, 5, 6, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "J", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x2, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0xa, 7, 8, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithByteArray:);
  methods[1].selector = @selector(initWithByteArray2:);
  methods[2].selector = @selector(buildDataArrayWithByteArray2:);
  methods[3].selector = @selector(initWithLibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_SourceArray:);
  methods[4].selector = @selector(nextBytesWithByteArray:);
  methods[5].selector = @selector(generateSeedWithInt:);
  methods[6].selector = @selector(nextInt);
  methods[7].selector = @selector(nextLong);
  methods[8].selector = @selector(isExhausted);
  methods[9].selector = @selector(nextValue);
  methods[10].selector = @selector(expandToBitLengthWithInt:withByteArray:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "REGULAR", "LJavaMathBigInteger;", .constantValue.asLong = 0, 0xa, -1, 9, -1, -1 },
    { "ANDROID", "LJavaMathBigInteger;", .constantValue.asLong = 0, 0xa, -1, 10, -1, -1 },
    { "CLASSPATH", "LJavaMathBigInteger;", .constantValue.asLong = 0, 0xa, -1, 11, -1, -1 },
    { "isAndroidStyle", "Z", .constantValue.asLong = 0, 0x1a, -1, 12, -1, -1 },
    { "isClasspathStyle", "Z", .constantValue.asLong = 0, 0x1a, -1, 13, -1, -1 },
    { "isRegularStyle", "Z", .constantValue.asLong = 0, 0x1a, -1, 14, -1, -1 },
    { "_data_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "_index_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "[B", "[[B", "buildDataArray", "[LLibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_Source;", "nextBytes", "generateSeed", "I", "expandToBitLength", "I[B", &LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_REGULAR, &LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_ANDROID, &LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_CLASSPATH, &LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_isAndroidStyle, &LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_isClasspathStyle, &LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_isRegularStyle, "LLibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_Source;LLibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_Data;LLibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_BigInteger;LLibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_RandomChecker;LLibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_DummyProvider;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom = { "UtilTestFixedSecureRandom", "lib.org.bouncycastle.util.test", ptrTable, methods, fields, 7, 0x1, 11, 8, -1, 15, -1, -1, -1 };
  return &_LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom;
}

+ (void)initialize {
  if (self == [LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom class]) {
    LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_REGULAR = new_JavaMathBigInteger_initWithNSString_withInt_(@"01020304ffffffff0506070811111111", 16);
    LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_ANDROID = new_JavaMathBigInteger_initWithNSString_withInt_(@"1111111105060708ffffffff01020304", 16);
    LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_CLASSPATH = new_JavaMathBigInteger_initWithNSString_withInt_(@"3020104ffffffff05060708111111", 16);
    {
      JavaMathBigInteger *check1 = new_JavaMathBigInteger_initWithInt_withJavaUtilRandom_(128, new_LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_RandomChecker_init());
      JavaMathBigInteger *check2 = new_JavaMathBigInteger_initWithInt_withJavaUtilRandom_(120, new_LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_RandomChecker_init());
      LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_isAndroidStyle = [check1 isEqual:LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_ANDROID];
      LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_isRegularStyle = [check1 isEqual:LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_REGULAR];
      LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_isClasspathStyle = [check2 isEqual:LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_CLASSPATH];
    }
    J2OBJC_SET_INITIALIZED(LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom)
  }
}

@end

void LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_initWithByteArray_(LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom *self, IOSByteArray *value) {
  LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_initWithLibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_SourceArray_(self, [IOSObjectArray newArrayWithObjects:(id[]){ create_LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_Data_initWithByteArray_(value) } count:1 type:LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_Source_class_()]);
}

LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom *new_LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_initWithByteArray_(IOSByteArray *value) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom, initWithByteArray_, value)
}

LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom *create_LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_initWithByteArray_(IOSByteArray *value) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom, initWithByteArray_, value)
}

void LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_initWithByteArray2_(LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom *self, IOSObjectArray *values) {
  LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_initWithLibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_SourceArray_(self, LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_buildDataArrayWithByteArray2_(values));
}

LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom *new_LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_initWithByteArray2_(IOSObjectArray *values) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom, initWithByteArray2_, values)
}

LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom *create_LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_initWithByteArray2_(IOSObjectArray *values) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom, initWithByteArray2_, values)
}

IOSObjectArray *LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_buildDataArrayWithByteArray2_(IOSObjectArray *values) {
  LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_initialize();
  IOSObjectArray *res = [IOSObjectArray newArrayWithLength:((IOSObjectArray *) nil_chk(values))->size_ type:LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_Data_class_()];
  for (jint i = 0; i != values->size_; i++) {
    (void) IOSObjectArray_SetAndConsume(res, i, new_LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_Data_initWithByteArray_(IOSObjectArray_Get(values, i)));
  }
  return res;
}

void LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_initWithLibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_SourceArray_(LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom *self, IOSObjectArray *sources) {
  JavaSecuritySecureRandom_initWithJavaSecuritySecureRandomSpi_withJavaSecurityProvider_(self, nil, new_LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_DummyProvider_init());
  JavaIoByteArrayOutputStream *bOut = new_JavaIoByteArrayOutputStream_init();
  if (LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_isRegularStyle) {
    if (LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_isClasspathStyle) {
      for (jint i = 0; i != ((IOSObjectArray *) nil_chk(sources))->size_; i++) {
        @try {
          if ([IOSObjectArray_Get(sources, i) isKindOfClass:[LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_BigInteger class]]) {
            IOSByteArray *data = ((LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_Source *) nil_chk(IOSObjectArray_Get(sources, i)))->data_;
            jint len = ((IOSByteArray *) nil_chk(data))->size_ - (data->size_ % 4);
            for (jint w = data->size_ - len - 1; w >= 0; w--) {
              [bOut writeWithInt:IOSByteArray_Get(data, w)];
            }
            for (jint w = data->size_ - len; w < data->size_; w += 4) {
              [bOut writeWithByteArray:data withInt:w withInt:4];
            }
          }
          else {
            [bOut writeWithByteArray:((LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_Source *) nil_chk(IOSObjectArray_Get(sources, i)))->data_];
          }
        }
        @catch (JavaIoIOException *e) {
          @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"can't save value source.");
        }
      }
    }
    else {
      for (jint i = 0; i != ((IOSObjectArray *) nil_chk(sources))->size_; i++) {
        @try {
          [bOut writeWithByteArray:((LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_Source *) nil_chk(IOSObjectArray_Get(sources, i)))->data_];
        }
        @catch (JavaIoIOException *e) {
          @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"can't save value source.");
        }
      }
    }
  }
  else if (LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_isAndroidStyle) {
    for (jint i = 0; i != ((IOSObjectArray *) nil_chk(sources))->size_; i++) {
      @try {
        if ([IOSObjectArray_Get(sources, i) isKindOfClass:[LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_BigInteger class]]) {
          IOSByteArray *data = ((LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_Source *) nil_chk(IOSObjectArray_Get(sources, i)))->data_;
          jint len = ((IOSByteArray *) nil_chk(data))->size_ - (data->size_ % 4);
          for (jint w = 0; w < len; w += 4) {
            [bOut writeWithByteArray:data withInt:data->size_ - (w + 4) withInt:4];
          }
          if (data->size_ - len != 0) {
            for (jint w = 0; w != 4 - (data->size_ - len); w++) {
              [bOut writeWithInt:0];
            }
          }
          for (jint w = 0; w != data->size_ - len; w++) {
            [bOut writeWithInt:IOSByteArray_Get(data, len + w)];
          }
        }
        else {
          [bOut writeWithByteArray:((LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_Source *) nil_chk(IOSObjectArray_Get(sources, i)))->data_];
        }
      }
      @catch (JavaIoIOException *e) {
        @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"can't save value source.");
      }
    }
  }
  else {
    @throw new_JavaLangIllegalStateException_initWithNSString_(@"Unrecognized BigInteger implementation");
  }
  self->_data_ = [bOut toByteArray];
}

LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom *new_LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_initWithLibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_SourceArray_(IOSObjectArray *sources) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom, initWithLibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_SourceArray_, sources)
}

LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom *create_LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_initWithLibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_SourceArray_(IOSObjectArray *sources) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom, initWithLibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_SourceArray_, sources)
}

jint LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_nextValue(LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom *self) {
  return IOSByteArray_Get(nil_chk(self->_data_), self->_index_++) & (jint) 0xff;
}

IOSByteArray *LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_expandToBitLengthWithInt_withByteArray_(jint bitLength, IOSByteArray *v) {
  LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_initialize();
  if ((bitLength + 7) / 8 > ((IOSByteArray *) nil_chk(v))->size_) {
    IOSByteArray *tmp = [IOSByteArray newArrayWithLength:(bitLength + 7) / 8];
    JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(v, 0, tmp, tmp->size_ - v->size_, v->size_);
    if (LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_isAndroidStyle) {
      if (bitLength % 8 != 0) {
        jint i = LibOrgBouncycastleUtilPack_bigEndianToIntWithByteArray_withInt_(tmp, 0);
        LibOrgBouncycastleUtilPack_intToBigEndianWithInt_withByteArray_withInt_(JreLShift32(i, (8 - (bitLength % 8))), tmp, 0);
      }
    }
    return tmp;
  }
  else {
    if (LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_isAndroidStyle && bitLength < (v->size_ * 8)) {
      if (bitLength % 8 != 0) {
        jint i = LibOrgBouncycastleUtilPack_bigEndianToIntWithByteArray_withInt_(v, 0);
        LibOrgBouncycastleUtilPack_intToBigEndianWithInt_withByteArray_withInt_(JreLShift32(i, (8 - (bitLength % 8))), v, 0);
      }
    }
  }
  return v;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom)

@implementation LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_Source

- (instancetype)initWithByteArray:(IOSByteArray *)data {
  LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_Source_initWithByteArray_(self, data);
  return self;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x0, -1, 0, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithByteArray:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "data_", "[B", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "[B", "LLibOrgBouncycastleUtilTestUtilTestFixedSecureRandom;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_Source = { "Source", "lib.org.bouncycastle.util.test", ptrTable, methods, fields, 7, 0x9, 1, 1, 1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_Source;
}

@end

void LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_Source_initWithByteArray_(LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_Source *self, IOSByteArray *data) {
  NSObject_init(self);
  self->data_ = data;
}

LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_Source *new_LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_Source_initWithByteArray_(IOSByteArray *data) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_Source, initWithByteArray_, data)
}

LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_Source *create_LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_Source_initWithByteArray_(IOSByteArray *data) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_Source, initWithByteArray_, data)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_Source)

@implementation LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_Data

- (instancetype)initWithByteArray:(IOSByteArray *)data {
  LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_Data_initWithByteArray_(self, data);
  return self;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithByteArray:);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "[B", "LLibOrgBouncycastleUtilTestUtilTestFixedSecureRandom;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_Data = { "Data", "lib.org.bouncycastle.util.test", ptrTable, methods, NULL, 7, 0x9, 1, 0, 1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_Data;
}

@end

void LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_Data_initWithByteArray_(LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_Data *self, IOSByteArray *data) {
  LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_Source_initWithByteArray_(self, data);
}

LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_Data *new_LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_Data_initWithByteArray_(IOSByteArray *data) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_Data, initWithByteArray_, data)
}

LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_Data *create_LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_Data_initWithByteArray_(IOSByteArray *data) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_Data, initWithByteArray_, data)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_Data)

@implementation LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_BigInteger

- (instancetype)initWithByteArray:(IOSByteArray *)data {
  LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_BigInteger_initWithByteArray_(self, data);
  return self;
}

- (instancetype)initWithInt:(jint)bitLength
              withByteArray:(IOSByteArray *)data {
  LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_BigInteger_initWithInt_withByteArray_(self, bitLength, data);
  return self;
}

- (instancetype)initWithNSString:(NSString *)hexData {
  LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_BigInteger_initWithNSString_(self, hexData);
  return self;
}

- (instancetype)initWithInt:(jint)bitLength
               withNSString:(NSString *)hexData {
  LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_BigInteger_initWithInt_withNSString_(self, bitLength, hexData);
  return self;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 1, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 2, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 3, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithByteArray:);
  methods[1].selector = @selector(initWithInt:withByteArray:);
  methods[2].selector = @selector(initWithNSString:);
  methods[3].selector = @selector(initWithInt:withNSString:);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "[B", "I[B", "LNSString;", "ILNSString;", "LLibOrgBouncycastleUtilTestUtilTestFixedSecureRandom;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_BigInteger = { "BigInteger", "lib.org.bouncycastle.util.test", ptrTable, methods, NULL, 7, 0x9, 4, 0, 4, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_BigInteger;
}

@end

void LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_BigInteger_initWithByteArray_(LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_BigInteger *self, IOSByteArray *data) {
  LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_Source_initWithByteArray_(self, data);
}

LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_BigInteger *new_LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_BigInteger_initWithByteArray_(IOSByteArray *data) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_BigInteger, initWithByteArray_, data)
}

LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_BigInteger *create_LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_BigInteger_initWithByteArray_(IOSByteArray *data) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_BigInteger, initWithByteArray_, data)
}

void LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_BigInteger_initWithInt_withByteArray_(LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_BigInteger *self, jint bitLength, IOSByteArray *data) {
  LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_Source_initWithByteArray_(self, LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_expandToBitLengthWithInt_withByteArray_(bitLength, data));
}

LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_BigInteger *new_LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_BigInteger_initWithInt_withByteArray_(jint bitLength, IOSByteArray *data) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_BigInteger, initWithInt_withByteArray_, bitLength, data)
}

LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_BigInteger *create_LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_BigInteger_initWithInt_withByteArray_(jint bitLength, IOSByteArray *data) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_BigInteger, initWithInt_withByteArray_, bitLength, data)
}

void LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_BigInteger_initWithNSString_(LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_BigInteger *self, NSString *hexData) {
  LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_BigInteger_initWithByteArray_(self, LibOrgBouncycastleUtilEncodersHex_decodeWithNSString_(hexData));
}

LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_BigInteger *new_LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_BigInteger_initWithNSString_(NSString *hexData) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_BigInteger, initWithNSString_, hexData)
}

LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_BigInteger *create_LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_BigInteger_initWithNSString_(NSString *hexData) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_BigInteger, initWithNSString_, hexData)
}

void LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_BigInteger_initWithInt_withNSString_(LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_BigInteger *self, jint bitLength, NSString *hexData) {
  LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_Source_initWithByteArray_(self, LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_expandToBitLengthWithInt_withByteArray_(bitLength, LibOrgBouncycastleUtilEncodersHex_decodeWithNSString_(hexData)));
}

LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_BigInteger *new_LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_BigInteger_initWithInt_withNSString_(jint bitLength, NSString *hexData) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_BigInteger, initWithInt_withNSString_, bitLength, hexData)
}

LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_BigInteger *create_LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_BigInteger_initWithInt_withNSString_(jint bitLength, NSString *hexData) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_BigInteger, initWithInt_withNSString_, bitLength, hexData)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_BigInteger)

@implementation LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_RandomChecker

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_RandomChecker_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (void)nextBytesWithByteArray:(IOSByteArray *)bytes {
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(data_, index_, bytes, 0, ((IOSByteArray *) nil_chk(bytes))->size_);
  index_ += bytes->size_;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x0, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 0, 1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(nextBytesWithByteArray:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "data_", "[B", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "index_", "I", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "nextBytes", "[B", "LLibOrgBouncycastleUtilTestUtilTestFixedSecureRandom;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_RandomChecker = { "RandomChecker", "lib.org.bouncycastle.util.test", ptrTable, methods, fields, 7, 0xa, 2, 2, 2, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_RandomChecker;
}

@end

void LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_RandomChecker_init(LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_RandomChecker *self) {
  JavaSecuritySecureRandom_initWithJavaSecuritySecureRandomSpi_withJavaSecurityProvider_(self, nil, new_LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_DummyProvider_init());
  self->data_ = LibOrgBouncycastleUtilEncodersHex_decodeWithNSString_(@"01020304ffffffff0506070811111111");
  self->index_ = 0;
}

LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_RandomChecker *new_LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_RandomChecker_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_RandomChecker, init)
}

LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_RandomChecker *create_LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_RandomChecker_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_RandomChecker, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_RandomChecker)

@implementation LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_DummyProvider

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_DummyProvider_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x0, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "LLibOrgBouncycastleUtilTestUtilTestFixedSecureRandom;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_DummyProvider = { "DummyProvider", "lib.org.bouncycastle.util.test", ptrTable, methods, NULL, 7, 0xa, 1, 0, 0, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_DummyProvider;
}

@end

void LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_DummyProvider_init(LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_DummyProvider *self) {
  JavaSecurityProvider_initWithNSString_withDouble_withNSString_(self, @"BCFIPS_FIXED_RNG", 1.0, @"BCFIPS Fixed Secure Random Provider");
}

LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_DummyProvider *new_LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_DummyProvider_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_DummyProvider, init)
}

LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_DummyProvider *create_LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_DummyProvider_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_DummyProvider, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_DummyProvider)
