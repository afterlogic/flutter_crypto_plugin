//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jcajce/provider/asymmetric/util/DESUtil.java
//

#include "ASN1ObjectIdentifier.h"
#include "DESUtil.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "OIWObjectIdentifiers.h"
#include "PKCSObjectIdentifiers.h"
#include "Strings.h"
#include "java/util/HashSet.h"
#include "java/util/Set.h"

inline id<JavaUtilSet> LibOrgBouncycastleJcajceProviderAsymmetricUtilDESUtil_get_des(void);
static id<JavaUtilSet> LibOrgBouncycastleJcajceProviderAsymmetricUtilDESUtil_des;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleJcajceProviderAsymmetricUtilDESUtil, des, id<JavaUtilSet>)

J2OBJC_INITIALIZED_DEFN(LibOrgBouncycastleJcajceProviderAsymmetricUtilDESUtil)

@implementation LibOrgBouncycastleJcajceProviderAsymmetricUtilDESUtil

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceProviderAsymmetricUtilDESUtil_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

+ (jboolean)isDESWithNSString:(NSString *)algorithmID {
  return LibOrgBouncycastleJcajceProviderAsymmetricUtilDESUtil_isDESWithNSString_(algorithmID);
}

+ (void)setOddParityWithByteArray:(IOSByteArray *)bytes {
  LibOrgBouncycastleJcajceProviderAsymmetricUtilDESUtil_setOddParityWithByteArray_(bytes);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x9, 0, 1, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 2, 3, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(isDESWithNSString:);
  methods[2].selector = @selector(setOddParityWithByteArray:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "des", "LJavaUtilSet;", .constantValue.asLong = 0, 0x1a, -1, 4, 5, -1 },
  };
  static const void *ptrTable[] = { "isDES", "LNSString;", "setOddParity", "[B", &LibOrgBouncycastleJcajceProviderAsymmetricUtilDESUtil_des, "Ljava/util/Set<Ljava/lang/String;>;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderAsymmetricUtilDESUtil = { "DESUtil", "lib.org.bouncycastle.jcajce.provider.asymmetric.util", ptrTable, methods, fields, 7, 0x1, 3, 1, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderAsymmetricUtilDESUtil;
}

+ (void)initialize {
  if (self == [LibOrgBouncycastleJcajceProviderAsymmetricUtilDESUtil class]) {
    LibOrgBouncycastleJcajceProviderAsymmetricUtilDESUtil_des = new_JavaUtilHashSet_init();
    {
      [LibOrgBouncycastleJcajceProviderAsymmetricUtilDESUtil_des addWithId:@"DES"];
      [LibOrgBouncycastleJcajceProviderAsymmetricUtilDESUtil_des addWithId:@"DESEDE"];
      [LibOrgBouncycastleJcajceProviderAsymmetricUtilDESUtil_des addWithId:[((LibOrgBouncycastleAsn1ASN1ObjectIdentifier *) nil_chk(JreLoadStatic(LibOrgBouncycastleAsn1OiwOIWObjectIdentifiers, desCBC))) getId]];
      [LibOrgBouncycastleJcajceProviderAsymmetricUtilDESUtil_des addWithId:[((LibOrgBouncycastleAsn1ASN1ObjectIdentifier *) nil_chk(JreLoadStatic(LibOrgBouncycastleAsn1PkcsPKCSObjectIdentifiers, des_EDE3_CBC))) getId]];
      [LibOrgBouncycastleJcajceProviderAsymmetricUtilDESUtil_des addWithId:[JreLoadStatic(LibOrgBouncycastleAsn1PkcsPKCSObjectIdentifiers, des_EDE3_CBC) getId]];
      [LibOrgBouncycastleJcajceProviderAsymmetricUtilDESUtil_des addWithId:[((LibOrgBouncycastleAsn1ASN1ObjectIdentifier *) nil_chk(JreLoadStatic(LibOrgBouncycastleAsn1PkcsPKCSObjectIdentifiers, id_alg_CMS3DESwrap))) getId]];
    }
    J2OBJC_SET_INITIALIZED(LibOrgBouncycastleJcajceProviderAsymmetricUtilDESUtil)
  }
}

@end

void LibOrgBouncycastleJcajceProviderAsymmetricUtilDESUtil_init(LibOrgBouncycastleJcajceProviderAsymmetricUtilDESUtil *self) {
  NSObject_init(self);
}

LibOrgBouncycastleJcajceProviderAsymmetricUtilDESUtil *new_LibOrgBouncycastleJcajceProviderAsymmetricUtilDESUtil_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderAsymmetricUtilDESUtil, init)
}

LibOrgBouncycastleJcajceProviderAsymmetricUtilDESUtil *create_LibOrgBouncycastleJcajceProviderAsymmetricUtilDESUtil_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderAsymmetricUtilDESUtil, init)
}

jboolean LibOrgBouncycastleJcajceProviderAsymmetricUtilDESUtil_isDESWithNSString_(NSString *algorithmID) {
  LibOrgBouncycastleJcajceProviderAsymmetricUtilDESUtil_initialize();
  NSString *name = LibOrgBouncycastleUtilStrings_toUpperCaseWithNSString_(algorithmID);
  return [((id<JavaUtilSet>) nil_chk(LibOrgBouncycastleJcajceProviderAsymmetricUtilDESUtil_des)) containsWithId:name];
}

void LibOrgBouncycastleJcajceProviderAsymmetricUtilDESUtil_setOddParityWithByteArray_(IOSByteArray *bytes) {
  LibOrgBouncycastleJcajceProviderAsymmetricUtilDESUtil_initialize();
  for (jint i = 0; i < ((IOSByteArray *) nil_chk(bytes))->size_; i++) {
    jint b = IOSByteArray_Get(bytes, i);
    *IOSByteArray_GetRef(bytes, i) = (jbyte) ((b & (jint) 0xfe) | ((((JreRShift32(b, 1)) ^ (JreRShift32(b, 2)) ^ (JreRShift32(b, 3)) ^ (JreRShift32(b, 4)) ^ (JreRShift32(b, 5)) ^ (JreRShift32(b, 6)) ^ (JreRShift32(b, 7))) ^ (jint) 0x01) & (jint) 0x01));
  }
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderAsymmetricUtilDESUtil)
