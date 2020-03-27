//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/tls/TlsSRTPUtils.java
//

#include "AlertDescription.h"
#include "ExtensionType.h"
#include "IOSPrimitiveArray.h"
#include "Integers.h"
#include "J2ObjC_source.h"
#include "TlsFatalAlert.h"
#include "TlsProtocol.h"
#include "TlsSRTPUtils.h"
#include "TlsUtils.h"
#include "UseSRTPData.h"
#include "java/io/ByteArrayInputStream.h"
#include "java/io/ByteArrayOutputStream.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/lang/Integer.h"
#include "java/util/Hashtable.h"

J2OBJC_INITIALIZED_DEFN(LibOrgBouncycastleCryptoTlsTlsSRTPUtils)

JavaLangInteger *LibOrgBouncycastleCryptoTlsTlsSRTPUtils_EXT_use_srtp;

@implementation LibOrgBouncycastleCryptoTlsTlsSRTPUtils

+ (JavaLangInteger *)EXT_use_srtp {
  return LibOrgBouncycastleCryptoTlsTlsSRTPUtils_EXT_use_srtp;
}

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleCryptoTlsTlsSRTPUtils_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

+ (void)addUseSRTPExtensionWithJavaUtilHashtable:(JavaUtilHashtable *)extensions
      withLibOrgBouncycastleCryptoTlsUseSRTPData:(LibOrgBouncycastleCryptoTlsUseSRTPData *)useSRTPData {
  LibOrgBouncycastleCryptoTlsTlsSRTPUtils_addUseSRTPExtensionWithJavaUtilHashtable_withLibOrgBouncycastleCryptoTlsUseSRTPData_(extensions, useSRTPData);
}

+ (LibOrgBouncycastleCryptoTlsUseSRTPData *)getUseSRTPExtensionWithJavaUtilHashtable:(JavaUtilHashtable *)extensions {
  return LibOrgBouncycastleCryptoTlsTlsSRTPUtils_getUseSRTPExtensionWithJavaUtilHashtable_(extensions);
}

+ (IOSByteArray *)createUseSRTPExtensionWithLibOrgBouncycastleCryptoTlsUseSRTPData:(LibOrgBouncycastleCryptoTlsUseSRTPData *)useSRTPData {
  return LibOrgBouncycastleCryptoTlsTlsSRTPUtils_createUseSRTPExtensionWithLibOrgBouncycastleCryptoTlsUseSRTPData_(useSRTPData);
}

+ (LibOrgBouncycastleCryptoTlsUseSRTPData *)readUseSRTPExtensionWithByteArray:(IOSByteArray *)extensionData {
  return LibOrgBouncycastleCryptoTlsTlsSRTPUtils_readUseSRTPExtensionWithByteArray_(extensionData);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 0, 1, 2, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoTlsUseSRTPData;", 0x9, 3, 4, 2, -1, -1, -1 },
    { NULL, "[B", 0x9, 5, 6, 2, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoTlsUseSRTPData;", 0x9, 7, 8, 2, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(addUseSRTPExtensionWithJavaUtilHashtable:withLibOrgBouncycastleCryptoTlsUseSRTPData:);
  methods[2].selector = @selector(getUseSRTPExtensionWithJavaUtilHashtable:);
  methods[3].selector = @selector(createUseSRTPExtensionWithLibOrgBouncycastleCryptoTlsUseSRTPData:);
  methods[4].selector = @selector(readUseSRTPExtensionWithByteArray:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "EXT_use_srtp", "LJavaLangInteger;", .constantValue.asLong = 0, 0x19, -1, 9, -1, -1 },
  };
  static const void *ptrTable[] = { "addUseSRTPExtension", "LJavaUtilHashtable;LLibOrgBouncycastleCryptoTlsUseSRTPData;", "LJavaIoIOException;", "getUseSRTPExtension", "LJavaUtilHashtable;", "createUseSRTPExtension", "LLibOrgBouncycastleCryptoTlsUseSRTPData;", "readUseSRTPExtension", "[B", &LibOrgBouncycastleCryptoTlsTlsSRTPUtils_EXT_use_srtp };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoTlsTlsSRTPUtils = { "TlsSRTPUtils", "lib.org.bouncycastle.crypto.tls", ptrTable, methods, fields, 7, 0x1, 5, 1, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoTlsTlsSRTPUtils;
}

+ (void)initialize {
  if (self == [LibOrgBouncycastleCryptoTlsTlsSRTPUtils class]) {
    LibOrgBouncycastleCryptoTlsTlsSRTPUtils_EXT_use_srtp = LibOrgBouncycastleUtilIntegers_valueOfWithInt_(LibOrgBouncycastleCryptoTlsExtensionType_use_srtp);
    J2OBJC_SET_INITIALIZED(LibOrgBouncycastleCryptoTlsTlsSRTPUtils)
  }
}

@end

void LibOrgBouncycastleCryptoTlsTlsSRTPUtils_init(LibOrgBouncycastleCryptoTlsTlsSRTPUtils *self) {
  NSObject_init(self);
}

LibOrgBouncycastleCryptoTlsTlsSRTPUtils *new_LibOrgBouncycastleCryptoTlsTlsSRTPUtils_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoTlsTlsSRTPUtils, init)
}

LibOrgBouncycastleCryptoTlsTlsSRTPUtils *create_LibOrgBouncycastleCryptoTlsTlsSRTPUtils_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoTlsTlsSRTPUtils, init)
}

void LibOrgBouncycastleCryptoTlsTlsSRTPUtils_addUseSRTPExtensionWithJavaUtilHashtable_withLibOrgBouncycastleCryptoTlsUseSRTPData_(JavaUtilHashtable *extensions, LibOrgBouncycastleCryptoTlsUseSRTPData *useSRTPData) {
  LibOrgBouncycastleCryptoTlsTlsSRTPUtils_initialize();
  (void) [((JavaUtilHashtable *) nil_chk(extensions)) putWithId:LibOrgBouncycastleCryptoTlsTlsSRTPUtils_EXT_use_srtp withId:LibOrgBouncycastleCryptoTlsTlsSRTPUtils_createUseSRTPExtensionWithLibOrgBouncycastleCryptoTlsUseSRTPData_(useSRTPData)];
}

LibOrgBouncycastleCryptoTlsUseSRTPData *LibOrgBouncycastleCryptoTlsTlsSRTPUtils_getUseSRTPExtensionWithJavaUtilHashtable_(JavaUtilHashtable *extensions) {
  LibOrgBouncycastleCryptoTlsTlsSRTPUtils_initialize();
  IOSByteArray *extensionData = LibOrgBouncycastleCryptoTlsTlsUtils_getExtensionDataWithJavaUtilHashtable_withJavaLangInteger_(extensions, LibOrgBouncycastleCryptoTlsTlsSRTPUtils_EXT_use_srtp);
  return extensionData == nil ? nil : LibOrgBouncycastleCryptoTlsTlsSRTPUtils_readUseSRTPExtensionWithByteArray_(extensionData);
}

IOSByteArray *LibOrgBouncycastleCryptoTlsTlsSRTPUtils_createUseSRTPExtensionWithLibOrgBouncycastleCryptoTlsUseSRTPData_(LibOrgBouncycastleCryptoTlsUseSRTPData *useSRTPData) {
  LibOrgBouncycastleCryptoTlsTlsSRTPUtils_initialize();
  if (useSRTPData == nil) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"'useSRTPData' cannot be null");
  }
  JavaIoByteArrayOutputStream *buf = new_JavaIoByteArrayOutputStream_init();
  LibOrgBouncycastleCryptoTlsTlsUtils_writeUint16ArrayWithUint16LengthWithIntArray_withJavaIoOutputStream_([useSRTPData getProtectionProfiles], buf);
  LibOrgBouncycastleCryptoTlsTlsUtils_writeOpaque8WithByteArray_withJavaIoOutputStream_([useSRTPData getMki], buf);
  return [buf toByteArray];
}

LibOrgBouncycastleCryptoTlsUseSRTPData *LibOrgBouncycastleCryptoTlsTlsSRTPUtils_readUseSRTPExtensionWithByteArray_(IOSByteArray *extensionData) {
  LibOrgBouncycastleCryptoTlsTlsSRTPUtils_initialize();
  if (extensionData == nil) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"'extensionData' cannot be null");
  }
  JavaIoByteArrayInputStream *buf = new_JavaIoByteArrayInputStream_initWithByteArray_(extensionData);
  jint length = LibOrgBouncycastleCryptoTlsTlsUtils_readUint16WithJavaIoInputStream_(buf);
  if (length < 2 || (length & 1) != 0) {
    @throw new_LibOrgBouncycastleCryptoTlsTlsFatalAlert_initWithShort_(LibOrgBouncycastleCryptoTlsAlertDescription_decode_error);
  }
  IOSIntArray *protectionProfiles = LibOrgBouncycastleCryptoTlsTlsUtils_readUint16ArrayWithInt_withJavaIoInputStream_(length / 2, buf);
  IOSByteArray *mki = LibOrgBouncycastleCryptoTlsTlsUtils_readOpaque8WithJavaIoInputStream_(buf);
  LibOrgBouncycastleCryptoTlsTlsProtocol_assertEmptyWithJavaIoByteArrayInputStream_(buf);
  return new_LibOrgBouncycastleCryptoTlsUseSRTPData_initWithIntArray_withByteArray_(protectionProfiles, mki);
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoTlsTlsSRTPUtils)
