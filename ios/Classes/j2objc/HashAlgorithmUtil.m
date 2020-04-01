//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/com/afterlogic/pgp/algorithm/HashAlgorithmUtil.java
//

#include "HashAlgorithmTags.h"
#include "HashAlgorithmUtil.h"
#include "IOSObjectArray.h"
#include "J2ObjC_source.h"
#include "java/lang/Enum.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/lang/Integer.h"
#include "java/util/HashMap.h"
#include "java/util/Map.h"

@interface LibComAfterlogicPgpAlgorithmHashAlgorithmUtil () {
 @public
  jint algorithmId_;
}

@end

inline id<JavaUtilMap> LibComAfterlogicPgpAlgorithmHashAlgorithmUtil_get_MAP(void);
static id<JavaUtilMap> LibComAfterlogicPgpAlgorithmHashAlgorithmUtil_MAP;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibComAfterlogicPgpAlgorithmHashAlgorithmUtil, MAP, id<JavaUtilMap>)

__attribute__((unused)) static void LibComAfterlogicPgpAlgorithmHashAlgorithmUtil_initWithInt_withNSString_withInt_(LibComAfterlogicPgpAlgorithmHashAlgorithmUtil *self, jint id_, NSString *__name, jint __ordinal);

__attribute__((unused)) static LibComAfterlogicPgpAlgorithmHashAlgorithmUtil *new_LibComAfterlogicPgpAlgorithmHashAlgorithmUtil_initWithInt_withNSString_withInt_(jint id_, NSString *__name, jint __ordinal) NS_RETURNS_RETAINED;

J2OBJC_INITIALIZED_DEFN(LibComAfterlogicPgpAlgorithmHashAlgorithmUtil)

LibComAfterlogicPgpAlgorithmHashAlgorithmUtil *LibComAfterlogicPgpAlgorithmHashAlgorithmUtil_values_[11];

@implementation LibComAfterlogicPgpAlgorithmHashAlgorithmUtil

+ (LibComAfterlogicPgpAlgorithmHashAlgorithmUtil *)MD5 {
  return JreEnum(LibComAfterlogicPgpAlgorithmHashAlgorithmUtil, MD5);
}

+ (LibComAfterlogicPgpAlgorithmHashAlgorithmUtil *)SHA1 {
  return JreEnum(LibComAfterlogicPgpAlgorithmHashAlgorithmUtil, SHA1);
}

+ (LibComAfterlogicPgpAlgorithmHashAlgorithmUtil *)RIPEMD160 {
  return JreEnum(LibComAfterlogicPgpAlgorithmHashAlgorithmUtil, RIPEMD160);
}

+ (LibComAfterlogicPgpAlgorithmHashAlgorithmUtil *)DOUBLE_SHA {
  return JreEnum(LibComAfterlogicPgpAlgorithmHashAlgorithmUtil, DOUBLE_SHA);
}

+ (LibComAfterlogicPgpAlgorithmHashAlgorithmUtil *)MD2 {
  return JreEnum(LibComAfterlogicPgpAlgorithmHashAlgorithmUtil, MD2);
}

+ (LibComAfterlogicPgpAlgorithmHashAlgorithmUtil *)TIGER_192 {
  return JreEnum(LibComAfterlogicPgpAlgorithmHashAlgorithmUtil, TIGER_192);
}

+ (LibComAfterlogicPgpAlgorithmHashAlgorithmUtil *)HAVAL_5_160 {
  return JreEnum(LibComAfterlogicPgpAlgorithmHashAlgorithmUtil, HAVAL_5_160);
}

+ (LibComAfterlogicPgpAlgorithmHashAlgorithmUtil *)SHA256 {
  return JreEnum(LibComAfterlogicPgpAlgorithmHashAlgorithmUtil, SHA256);
}

+ (LibComAfterlogicPgpAlgorithmHashAlgorithmUtil *)SHA384 {
  return JreEnum(LibComAfterlogicPgpAlgorithmHashAlgorithmUtil, SHA384);
}

+ (LibComAfterlogicPgpAlgorithmHashAlgorithmUtil *)SHA512 {
  return JreEnum(LibComAfterlogicPgpAlgorithmHashAlgorithmUtil, SHA512);
}

+ (LibComAfterlogicPgpAlgorithmHashAlgorithmUtil *)SHA224 {
  return JreEnum(LibComAfterlogicPgpAlgorithmHashAlgorithmUtil, SHA224);
}

+ (LibComAfterlogicPgpAlgorithmHashAlgorithmUtil *)fromIdWithInt:(jint)id_ {
  return LibComAfterlogicPgpAlgorithmHashAlgorithmUtil_fromIdWithInt_(id_);
}

- (jint)getAlgorithmId {
  return algorithmId_;
}

+ (IOSObjectArray *)values {
  return LibComAfterlogicPgpAlgorithmHashAlgorithmUtil_values();
}

+ (LibComAfterlogicPgpAlgorithmHashAlgorithmUtil *)valueOfWithNSString:(NSString *)name {
  return LibComAfterlogicPgpAlgorithmHashAlgorithmUtil_valueOfWithNSString_(name);
}

- (LibComAfterlogicPgpAlgorithmHashAlgorithmUtil_Enum)toNSEnum {
  return (LibComAfterlogicPgpAlgorithmHashAlgorithmUtil_Enum)[self ordinal];
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, "LLibComAfterlogicPgpAlgorithmHashAlgorithmUtil;", 0x9, 0, 1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[LLibComAfterlogicPgpAlgorithmHashAlgorithmUtil;", 0x9, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibComAfterlogicPgpAlgorithmHashAlgorithmUtil;", 0x9, 2, 3, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(fromIdWithInt:);
  methods[1].selector = @selector(getAlgorithmId);
  methods[2].selector = @selector(values);
  methods[3].selector = @selector(valueOfWithNSString:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "MD5", "LLibComAfterlogicPgpAlgorithmHashAlgorithmUtil;", .constantValue.asLong = 0, 0x4019, -1, 4, -1, -1 },
    { "SHA1", "LLibComAfterlogicPgpAlgorithmHashAlgorithmUtil;", .constantValue.asLong = 0, 0x4019, -1, 5, -1, -1 },
    { "RIPEMD160", "LLibComAfterlogicPgpAlgorithmHashAlgorithmUtil;", .constantValue.asLong = 0, 0x4019, -1, 6, -1, -1 },
    { "DOUBLE_SHA", "LLibComAfterlogicPgpAlgorithmHashAlgorithmUtil;", .constantValue.asLong = 0, 0x4019, -1, 7, -1, -1 },
    { "MD2", "LLibComAfterlogicPgpAlgorithmHashAlgorithmUtil;", .constantValue.asLong = 0, 0x4019, -1, 8, -1, -1 },
    { "TIGER_192", "LLibComAfterlogicPgpAlgorithmHashAlgorithmUtil;", .constantValue.asLong = 0, 0x4019, -1, 9, -1, -1 },
    { "HAVAL_5_160", "LLibComAfterlogicPgpAlgorithmHashAlgorithmUtil;", .constantValue.asLong = 0, 0x4019, -1, 10, -1, -1 },
    { "SHA256", "LLibComAfterlogicPgpAlgorithmHashAlgorithmUtil;", .constantValue.asLong = 0, 0x4019, -1, 11, -1, -1 },
    { "SHA384", "LLibComAfterlogicPgpAlgorithmHashAlgorithmUtil;", .constantValue.asLong = 0, 0x4019, -1, 12, -1, -1 },
    { "SHA512", "LLibComAfterlogicPgpAlgorithmHashAlgorithmUtil;", .constantValue.asLong = 0, 0x4019, -1, 13, -1, -1 },
    { "SHA224", "LLibComAfterlogicPgpAlgorithmHashAlgorithmUtil;", .constantValue.asLong = 0, 0x4019, -1, 14, -1, -1 },
    { "MAP", "LJavaUtilMap;", .constantValue.asLong = 0, 0x1a, -1, 15, 16, -1 },
    { "algorithmId_", "I", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "fromId", "I", "valueOf", "LNSString;", &JreEnum(LibComAfterlogicPgpAlgorithmHashAlgorithmUtil, MD5), &JreEnum(LibComAfterlogicPgpAlgorithmHashAlgorithmUtil, SHA1), &JreEnum(LibComAfterlogicPgpAlgorithmHashAlgorithmUtil, RIPEMD160), &JreEnum(LibComAfterlogicPgpAlgorithmHashAlgorithmUtil, DOUBLE_SHA), &JreEnum(LibComAfterlogicPgpAlgorithmHashAlgorithmUtil, MD2), &JreEnum(LibComAfterlogicPgpAlgorithmHashAlgorithmUtil, TIGER_192), &JreEnum(LibComAfterlogicPgpAlgorithmHashAlgorithmUtil, HAVAL_5_160), &JreEnum(LibComAfterlogicPgpAlgorithmHashAlgorithmUtil, SHA256), &JreEnum(LibComAfterlogicPgpAlgorithmHashAlgorithmUtil, SHA384), &JreEnum(LibComAfterlogicPgpAlgorithmHashAlgorithmUtil, SHA512), &JreEnum(LibComAfterlogicPgpAlgorithmHashAlgorithmUtil, SHA224), &LibComAfterlogicPgpAlgorithmHashAlgorithmUtil_MAP, "Ljava/util/Map<Ljava/lang/Integer;Llib/com/afterlogic/pgp/algorithm/HashAlgorithmUtil;>;", "Ljava/lang/Enum<Llib/com/afterlogic/pgp/algorithm/HashAlgorithmUtil;>;" };
  static const J2ObjcClassInfo _LibComAfterlogicPgpAlgorithmHashAlgorithmUtil = { "HashAlgorithmUtil", "lib.com.afterlogic.pgp.algorithm", ptrTable, methods, fields, 7, 0x4011, 4, 13, -1, -1, -1, 17, -1 };
  return &_LibComAfterlogicPgpAlgorithmHashAlgorithmUtil;
}

+ (void)initialize {
  if (self == [LibComAfterlogicPgpAlgorithmHashAlgorithmUtil class]) {
    JreEnum(LibComAfterlogicPgpAlgorithmHashAlgorithmUtil, MD5) = new_LibComAfterlogicPgpAlgorithmHashAlgorithmUtil_initWithInt_withNSString_withInt_(LibOrgBouncycastleBcpgHashAlgorithmTags_MD5, JreEnumConstantName(LibComAfterlogicPgpAlgorithmHashAlgorithmUtil_class_(), 0), 0);
    JreEnum(LibComAfterlogicPgpAlgorithmHashAlgorithmUtil, SHA1) = new_LibComAfterlogicPgpAlgorithmHashAlgorithmUtil_initWithInt_withNSString_withInt_(LibOrgBouncycastleBcpgHashAlgorithmTags_SHA1, JreEnumConstantName(LibComAfterlogicPgpAlgorithmHashAlgorithmUtil_class_(), 1), 1);
    JreEnum(LibComAfterlogicPgpAlgorithmHashAlgorithmUtil, RIPEMD160) = new_LibComAfterlogicPgpAlgorithmHashAlgorithmUtil_initWithInt_withNSString_withInt_(LibOrgBouncycastleBcpgHashAlgorithmTags_RIPEMD160, JreEnumConstantName(LibComAfterlogicPgpAlgorithmHashAlgorithmUtil_class_(), 2), 2);
    JreEnum(LibComAfterlogicPgpAlgorithmHashAlgorithmUtil, DOUBLE_SHA) = new_LibComAfterlogicPgpAlgorithmHashAlgorithmUtil_initWithInt_withNSString_withInt_(LibOrgBouncycastleBcpgHashAlgorithmTags_DOUBLE_SHA, JreEnumConstantName(LibComAfterlogicPgpAlgorithmHashAlgorithmUtil_class_(), 3), 3);
    JreEnum(LibComAfterlogicPgpAlgorithmHashAlgorithmUtil, MD2) = new_LibComAfterlogicPgpAlgorithmHashAlgorithmUtil_initWithInt_withNSString_withInt_(LibOrgBouncycastleBcpgHashAlgorithmTags_MD2, JreEnumConstantName(LibComAfterlogicPgpAlgorithmHashAlgorithmUtil_class_(), 4), 4);
    JreEnum(LibComAfterlogicPgpAlgorithmHashAlgorithmUtil, TIGER_192) = new_LibComAfterlogicPgpAlgorithmHashAlgorithmUtil_initWithInt_withNSString_withInt_(LibOrgBouncycastleBcpgHashAlgorithmTags_TIGER_192, JreEnumConstantName(LibComAfterlogicPgpAlgorithmHashAlgorithmUtil_class_(), 5), 5);
    JreEnum(LibComAfterlogicPgpAlgorithmHashAlgorithmUtil, HAVAL_5_160) = new_LibComAfterlogicPgpAlgorithmHashAlgorithmUtil_initWithInt_withNSString_withInt_(LibOrgBouncycastleBcpgHashAlgorithmTags_HAVAL_5_160, JreEnumConstantName(LibComAfterlogicPgpAlgorithmHashAlgorithmUtil_class_(), 6), 6);
    JreEnum(LibComAfterlogicPgpAlgorithmHashAlgorithmUtil, SHA256) = new_LibComAfterlogicPgpAlgorithmHashAlgorithmUtil_initWithInt_withNSString_withInt_(LibOrgBouncycastleBcpgHashAlgorithmTags_SHA256, JreEnumConstantName(LibComAfterlogicPgpAlgorithmHashAlgorithmUtil_class_(), 7), 7);
    JreEnum(LibComAfterlogicPgpAlgorithmHashAlgorithmUtil, SHA384) = new_LibComAfterlogicPgpAlgorithmHashAlgorithmUtil_initWithInt_withNSString_withInt_(LibOrgBouncycastleBcpgHashAlgorithmTags_SHA384, JreEnumConstantName(LibComAfterlogicPgpAlgorithmHashAlgorithmUtil_class_(), 8), 8);
    JreEnum(LibComAfterlogicPgpAlgorithmHashAlgorithmUtil, SHA512) = new_LibComAfterlogicPgpAlgorithmHashAlgorithmUtil_initWithInt_withNSString_withInt_(LibOrgBouncycastleBcpgHashAlgorithmTags_SHA512, JreEnumConstantName(LibComAfterlogicPgpAlgorithmHashAlgorithmUtil_class_(), 9), 9);
    JreEnum(LibComAfterlogicPgpAlgorithmHashAlgorithmUtil, SHA224) = new_LibComAfterlogicPgpAlgorithmHashAlgorithmUtil_initWithInt_withNSString_withInt_(LibOrgBouncycastleBcpgHashAlgorithmTags_SHA224, JreEnumConstantName(LibComAfterlogicPgpAlgorithmHashAlgorithmUtil_class_(), 10), 10);
    LibComAfterlogicPgpAlgorithmHashAlgorithmUtil_MAP = new_JavaUtilHashMap_init();
    {
      {
        IOSObjectArray *a__ = LibComAfterlogicPgpAlgorithmHashAlgorithmUtil_values();
        LibComAfterlogicPgpAlgorithmHashAlgorithmUtil * const *b__ = ((IOSObjectArray *) nil_chk(a__))->buffer_;
        LibComAfterlogicPgpAlgorithmHashAlgorithmUtil * const *e__ = b__ + a__->size_;
        while (b__ < e__) {
          LibComAfterlogicPgpAlgorithmHashAlgorithmUtil *h = *b__++;
          (void) [LibComAfterlogicPgpAlgorithmHashAlgorithmUtil_MAP putWithId:JavaLangInteger_valueOfWithInt_(((LibComAfterlogicPgpAlgorithmHashAlgorithmUtil *) nil_chk(h))->algorithmId_) withId:h];
        }
      }
    }
    J2OBJC_SET_INITIALIZED(LibComAfterlogicPgpAlgorithmHashAlgorithmUtil)
  }
}

@end

LibComAfterlogicPgpAlgorithmHashAlgorithmUtil *LibComAfterlogicPgpAlgorithmHashAlgorithmUtil_fromIdWithInt_(jint id_) {
  LibComAfterlogicPgpAlgorithmHashAlgorithmUtil_initialize();
  return [((id<JavaUtilMap>) nil_chk(LibComAfterlogicPgpAlgorithmHashAlgorithmUtil_MAP)) getWithId:JavaLangInteger_valueOfWithInt_(id_)];
}

void LibComAfterlogicPgpAlgorithmHashAlgorithmUtil_initWithInt_withNSString_withInt_(LibComAfterlogicPgpAlgorithmHashAlgorithmUtil *self, jint id_, NSString *__name, jint __ordinal) {
  JavaLangEnum_initWithNSString_withInt_(self, __name, __ordinal);
  self->algorithmId_ = id_;
}

LibComAfterlogicPgpAlgorithmHashAlgorithmUtil *new_LibComAfterlogicPgpAlgorithmHashAlgorithmUtil_initWithInt_withNSString_withInt_(jint id_, NSString *__name, jint __ordinal) {
  J2OBJC_NEW_IMPL(LibComAfterlogicPgpAlgorithmHashAlgorithmUtil, initWithInt_withNSString_withInt_, id_, __name, __ordinal)
}

IOSObjectArray *LibComAfterlogicPgpAlgorithmHashAlgorithmUtil_values() {
  LibComAfterlogicPgpAlgorithmHashAlgorithmUtil_initialize();
  return [IOSObjectArray arrayWithObjects:LibComAfterlogicPgpAlgorithmHashAlgorithmUtil_values_ count:11 type:LibComAfterlogicPgpAlgorithmHashAlgorithmUtil_class_()];
}

LibComAfterlogicPgpAlgorithmHashAlgorithmUtil *LibComAfterlogicPgpAlgorithmHashAlgorithmUtil_valueOfWithNSString_(NSString *name) {
  LibComAfterlogicPgpAlgorithmHashAlgorithmUtil_initialize();
  for (int i = 0; i < 11; i++) {
    LibComAfterlogicPgpAlgorithmHashAlgorithmUtil *e = LibComAfterlogicPgpAlgorithmHashAlgorithmUtil_values_[i];
    if ([name isEqual:[e name]]) {
      return e;
    }
  }
  @throw create_JavaLangIllegalArgumentException_initWithNSString_(name);
  return nil;
}

LibComAfterlogicPgpAlgorithmHashAlgorithmUtil *LibComAfterlogicPgpAlgorithmHashAlgorithmUtil_fromOrdinal(NSUInteger ordinal) {
  LibComAfterlogicPgpAlgorithmHashAlgorithmUtil_initialize();
  if (ordinal >= 11) {
    return nil;
  }
  return LibComAfterlogicPgpAlgorithmHashAlgorithmUtil_values_[ordinal];
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibComAfterlogicPgpAlgorithmHashAlgorithmUtil)