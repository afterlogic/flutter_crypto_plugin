//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/pqc/math/ntru/util/Util.java
//

#include "DenseTernaryPolynomial.h"
#include "IOSPrimitiveArray.h"
#include "IntEuclidean.h"
#include "Integers.h"
#include "J2ObjC_source.h"
#include "SparseTernaryPolynomial.h"
#include "TernaryPolynomial.h"
#include "Util.h"
#include "java/io/IOException.h"
#include "java/io/InputStream.h"
#include "java/lang/Integer.h"
#include "java/lang/System.h"
#include "java/security/SecureRandom.h"
#include "java/util/ArrayList.h"
#include "java/util/Collections.h"
#include "java/util/List.h"

inline jboolean LibOrgBouncycastlePqcMathNtruUtilUtil_get_IS_64_BITNESS_KNOWN(void);
inline jboolean LibOrgBouncycastlePqcMathNtruUtilUtil_set_IS_64_BITNESS_KNOWN(jboolean value);
static volatile_jboolean LibOrgBouncycastlePqcMathNtruUtilUtil_IS_64_BITNESS_KNOWN;
J2OBJC_STATIC_FIELD_PRIMITIVE_VOLATILE(LibOrgBouncycastlePqcMathNtruUtilUtil, IS_64_BITNESS_KNOWN, jboolean)

inline jboolean LibOrgBouncycastlePqcMathNtruUtilUtil_get_IS_64_BIT_JVM(void);
inline jboolean LibOrgBouncycastlePqcMathNtruUtilUtil_set_IS_64_BIT_JVM(jboolean value);
static volatile_jboolean LibOrgBouncycastlePqcMathNtruUtilUtil_IS_64_BIT_JVM;
J2OBJC_STATIC_FIELD_PRIMITIVE_VOLATILE(LibOrgBouncycastlePqcMathNtruUtilUtil, IS_64_BIT_JVM, jboolean)

@implementation LibOrgBouncycastlePqcMathNtruUtilUtil

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastlePqcMathNtruUtilUtil_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

+ (jint)invertWithInt:(jint)n
              withInt:(jint)modulus {
  return LibOrgBouncycastlePqcMathNtruUtilUtil_invertWithInt_withInt_(n, modulus);
}

+ (jint)powWithInt:(jint)a
           withInt:(jint)b
           withInt:(jint)modulus {
  return LibOrgBouncycastlePqcMathNtruUtilUtil_powWithInt_withInt_withInt_(a, b, modulus);
}

+ (jlong)powWithLong:(jlong)a
             withInt:(jint)b
            withLong:(jlong)modulus {
  return LibOrgBouncycastlePqcMathNtruUtilUtil_powWithLong_withInt_withLong_(a, b, modulus);
}

+ (id<LibOrgBouncycastlePqcMathNtruPolynomialTernaryPolynomial>)generateRandomTernaryWithInt:(jint)N
                                                                                     withInt:(jint)numOnes
                                                                                     withInt:(jint)numNegOnes
                                                                                 withBoolean:(jboolean)sparse
                                                                withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random {
  return LibOrgBouncycastlePqcMathNtruUtilUtil_generateRandomTernaryWithInt_withInt_withInt_withBoolean_withJavaSecuritySecureRandom_(N, numOnes, numNegOnes, sparse, random);
}

+ (IOSIntArray *)generateRandomTernaryWithInt:(jint)N
                                      withInt:(jint)numOnes
                                      withInt:(jint)numNegOnes
                 withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random {
  return LibOrgBouncycastlePqcMathNtruUtilUtil_generateRandomTernaryWithInt_withInt_withInt_withJavaSecuritySecureRandom_(N, numOnes, numNegOnes, random);
}

+ (jboolean)is64BitJVM {
  return LibOrgBouncycastlePqcMathNtruUtilUtil_is64BitJVM();
}

+ (IOSByteArray *)readFullLengthWithJavaIoInputStream:(JavaIoInputStream *)is
                                              withInt:(jint)length {
  return LibOrgBouncycastlePqcMathNtruUtilUtil_readFullLengthWithJavaIoInputStream_withInt_(is, length);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x9, 0, 1, -1, -1, -1, -1 },
    { NULL, "I", 0x9, 2, 3, -1, -1, -1, -1 },
    { NULL, "J", 0x9, 2, 4, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastlePqcMathNtruPolynomialTernaryPolynomial;", 0x9, 5, 6, -1, -1, -1, -1 },
    { NULL, "[I", 0x9, 5, 7, -1, -1, -1, -1 },
    { NULL, "Z", 0x9, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x9, 8, 9, 10, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(invertWithInt:withInt:);
  methods[2].selector = @selector(powWithInt:withInt:withInt:);
  methods[3].selector = @selector(powWithLong:withInt:withLong:);
  methods[4].selector = @selector(generateRandomTernaryWithInt:withInt:withInt:withBoolean:withJavaSecuritySecureRandom:);
  methods[5].selector = @selector(generateRandomTernaryWithInt:withInt:withInt:withJavaSecuritySecureRandom:);
  methods[6].selector = @selector(is64BitJVM);
  methods[7].selector = @selector(readFullLengthWithJavaIoInputStream:withInt:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "IS_64_BITNESS_KNOWN", "Z", .constantValue.asLong = 0, 0x4a, -1, 11, -1, -1 },
    { "IS_64_BIT_JVM", "Z", .constantValue.asLong = 0, 0x4a, -1, 12, -1, -1 },
  };
  static const void *ptrTable[] = { "invert", "II", "pow", "III", "JIJ", "generateRandomTernary", "IIIZLJavaSecuritySecureRandom;", "IIILJavaSecuritySecureRandom;", "readFullLength", "LJavaIoInputStream;I", "LJavaIoIOException;", &LibOrgBouncycastlePqcMathNtruUtilUtil_IS_64_BITNESS_KNOWN, &LibOrgBouncycastlePqcMathNtruUtilUtil_IS_64_BIT_JVM };
  static const J2ObjcClassInfo _LibOrgBouncycastlePqcMathNtruUtilUtil = { "Util", "lib.org.bouncycastle.pqc.math.ntru.util", ptrTable, methods, fields, 7, 0x1, 8, 2, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastlePqcMathNtruUtilUtil;
}

@end

void LibOrgBouncycastlePqcMathNtruUtilUtil_init(LibOrgBouncycastlePqcMathNtruUtilUtil *self) {
  NSObject_init(self);
}

LibOrgBouncycastlePqcMathNtruUtilUtil *new_LibOrgBouncycastlePqcMathNtruUtilUtil_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastlePqcMathNtruUtilUtil, init)
}

LibOrgBouncycastlePqcMathNtruUtilUtil *create_LibOrgBouncycastlePqcMathNtruUtilUtil_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastlePqcMathNtruUtilUtil, init)
}

jint LibOrgBouncycastlePqcMathNtruUtilUtil_invertWithInt_withInt_(jint n, jint modulus) {
  LibOrgBouncycastlePqcMathNtruUtilUtil_initialize();
  n %= modulus;
  if (n < 0) {
    n += modulus;
  }
  return ((LibOrgBouncycastlePqcMathNtruEuclidIntEuclidean *) nil_chk(LibOrgBouncycastlePqcMathNtruEuclidIntEuclidean_calculateWithInt_withInt_(n, modulus)))->x_;
}

jint LibOrgBouncycastlePqcMathNtruUtilUtil_powWithInt_withInt_withInt_(jint a, jint b, jint modulus) {
  LibOrgBouncycastlePqcMathNtruUtilUtil_initialize();
  jint p = 1;
  for (jint i = 0; i < b; i++) {
    p = (p * a) % modulus;
  }
  return p;
}

jlong LibOrgBouncycastlePqcMathNtruUtilUtil_powWithLong_withInt_withLong_(jlong a, jint b, jlong modulus) {
  LibOrgBouncycastlePqcMathNtruUtilUtil_initialize();
  jlong p = 1;
  for (jint i = 0; i < b; i++) {
    p = (p * a) % modulus;
  }
  return p;
}

id<LibOrgBouncycastlePqcMathNtruPolynomialTernaryPolynomial> LibOrgBouncycastlePqcMathNtruUtilUtil_generateRandomTernaryWithInt_withInt_withInt_withBoolean_withJavaSecuritySecureRandom_(jint N, jint numOnes, jint numNegOnes, jboolean sparse, JavaSecuritySecureRandom *random) {
  LibOrgBouncycastlePqcMathNtruUtilUtil_initialize();
  if (sparse) {
    return LibOrgBouncycastlePqcMathNtruPolynomialSparseTernaryPolynomial_generateRandomWithInt_withInt_withInt_withJavaSecuritySecureRandom_(N, numOnes, numNegOnes, random);
  }
  else {
    return LibOrgBouncycastlePqcMathNtruPolynomialDenseTernaryPolynomial_generateRandomWithInt_withInt_withInt_withJavaSecuritySecureRandom_(N, numOnes, numNegOnes, random);
  }
}

IOSIntArray *LibOrgBouncycastlePqcMathNtruUtilUtil_generateRandomTernaryWithInt_withInt_withInt_withJavaSecuritySecureRandom_(jint N, jint numOnes, jint numNegOnes, JavaSecuritySecureRandom *random) {
  LibOrgBouncycastlePqcMathNtruUtilUtil_initialize();
  JavaLangInteger *one = LibOrgBouncycastleUtilIntegers_valueOfWithInt_(1);
  JavaLangInteger *minusOne = LibOrgBouncycastleUtilIntegers_valueOfWithInt_(-1);
  JavaLangInteger *zero = LibOrgBouncycastleUtilIntegers_valueOfWithInt_(0);
  id<JavaUtilList> list = new_JavaUtilArrayList_init();
  for (jint i = 0; i < numOnes; i++) {
    [list addWithId:one];
  }
  for (jint i = 0; i < numNegOnes; i++) {
    [list addWithId:minusOne];
  }
  while ([list size] < N) {
    [list addWithId:zero];
  }
  JavaUtilCollections_shuffleWithJavaUtilList_withJavaUtilRandom_(list, random);
  IOSIntArray *arr = [IOSIntArray newArrayWithLength:N];
  for (jint i = 0; i < N; i++) {
    *IOSIntArray_GetRef(arr, i) = [((JavaLangInteger *) nil_chk(((JavaLangInteger *) cast_chk([list getWithInt:i], [JavaLangInteger class])))) intValue];
  }
  return arr;
}

jboolean LibOrgBouncycastlePqcMathNtruUtilUtil_is64BitJVM() {
  LibOrgBouncycastlePqcMathNtruUtilUtil_initialize();
  if (!JreLoadVolatileBoolean(&LibOrgBouncycastlePqcMathNtruUtilUtil_IS_64_BITNESS_KNOWN)) {
    NSString *arch = JavaLangSystem_getPropertyWithNSString_(@"os.arch");
    NSString *sunModel = JavaLangSystem_getPropertyWithNSString_(@"sun.arch.data.model");
    JreAssignVolatileBoolean(&LibOrgBouncycastlePqcMathNtruUtilUtil_IS_64_BIT_JVM, [@"amd64" isEqual:arch] || [@"x86_64" isEqual:arch] || [@"ppc64" isEqual:arch] || [@"64" isEqual:sunModel]);
    JreAssignVolatileBoolean(&LibOrgBouncycastlePqcMathNtruUtilUtil_IS_64_BITNESS_KNOWN, true);
  }
  return JreLoadVolatileBoolean(&LibOrgBouncycastlePqcMathNtruUtilUtil_IS_64_BIT_JVM);
}

IOSByteArray *LibOrgBouncycastlePqcMathNtruUtilUtil_readFullLengthWithJavaIoInputStream_withInt_(JavaIoInputStream *is, jint length) {
  LibOrgBouncycastlePqcMathNtruUtilUtil_initialize();
  IOSByteArray *arr = [IOSByteArray newArrayWithLength:length];
  if ([((JavaIoInputStream *) nil_chk(is)) readWithByteArray:arr] != arr->size_) {
    @throw new_JavaIoIOException_initWithNSString_(@"Not enough bytes to read.");
  }
  return arr;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastlePqcMathNtruUtilUtil)