//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/x509/extension/X509ExtensionUtil.java
//

#include "ASN1Encodable.h"
#include "ASN1ObjectIdentifier.h"
#include "ASN1OctetString.h"
#include "ASN1Primitive.h"
#include "ASN1Sequence.h"
#include "ASN1String.h"
#include "Extension.h"
#include "GeneralName.h"
#include "IOSClass.h"
#include "IOSPrimitiveArray.h"
#include "Integers.h"
#include "J2ObjC_source.h"
#include "X500Name.h"
#include "X509ExtensionUtil.h"
#include "java/io/IOException.h"
#include "java/lang/Exception.h"
#include "java/lang/Integer.h"
#include "java/security/cert/CertificateParsingException.h"
#include "java/security/cert/X509Certificate.h"
#include "java/util/ArrayList.h"
#include "java/util/Collection.h"
#include "java/util/Collections.h"
#include "java/util/Enumeration.h"
#include "java/util/List.h"

@interface LibOrgBouncycastleX509ExtensionX509ExtensionUtil ()

+ (id<JavaUtilCollection>)getAlternativeNamesWithByteArray:(IOSByteArray *)extVal;

@end

__attribute__((unused)) static id<JavaUtilCollection> LibOrgBouncycastleX509ExtensionX509ExtensionUtil_getAlternativeNamesWithByteArray_(IOSByteArray *extVal);

@implementation LibOrgBouncycastleX509ExtensionX509ExtensionUtil

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleX509ExtensionX509ExtensionUtil_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

+ (LibOrgBouncycastleAsn1ASN1Primitive *)fromExtensionValueWithByteArray:(IOSByteArray *)encodedValue {
  return LibOrgBouncycastleX509ExtensionX509ExtensionUtil_fromExtensionValueWithByteArray_(encodedValue);
}

+ (id<JavaUtilCollection>)getIssuerAlternativeNamesWithJavaSecurityCertX509Certificate:(JavaSecurityCertX509Certificate *)cert {
  return LibOrgBouncycastleX509ExtensionX509ExtensionUtil_getIssuerAlternativeNamesWithJavaSecurityCertX509Certificate_(cert);
}

+ (id<JavaUtilCollection>)getSubjectAlternativeNamesWithJavaSecurityCertX509Certificate:(JavaSecurityCertX509Certificate *)cert {
  return LibOrgBouncycastleX509ExtensionX509ExtensionUtil_getSubjectAlternativeNamesWithJavaSecurityCertX509Certificate_(cert);
}

+ (id<JavaUtilCollection>)getAlternativeNamesWithByteArray:(IOSByteArray *)extVal {
  return LibOrgBouncycastleX509ExtensionX509ExtensionUtil_getAlternativeNamesWithByteArray_(extVal);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Primitive;", 0x9, 0, 1, 2, -1, -1, -1 },
    { NULL, "LJavaUtilCollection;", 0x9, 3, 4, 5, -1, -1, -1 },
    { NULL, "LJavaUtilCollection;", 0x9, 6, 4, 5, -1, -1, -1 },
    { NULL, "LJavaUtilCollection;", 0xa, 7, 1, 5, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(fromExtensionValueWithByteArray:);
  methods[2].selector = @selector(getIssuerAlternativeNamesWithJavaSecurityCertX509Certificate:);
  methods[3].selector = @selector(getSubjectAlternativeNamesWithJavaSecurityCertX509Certificate:);
  methods[4].selector = @selector(getAlternativeNamesWithByteArray:);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "fromExtensionValue", "[B", "LJavaIoIOException;", "getIssuerAlternativeNames", "LJavaSecurityCertX509Certificate;", "LJavaSecurityCertCertificateParsingException;", "getSubjectAlternativeNames", "getAlternativeNames" };
  static const J2ObjcClassInfo _LibOrgBouncycastleX509ExtensionX509ExtensionUtil = { "X509ExtensionUtil", "lib.org.bouncycastle.x509.extension", ptrTable, methods, NULL, 7, 0x1, 5, 0, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleX509ExtensionX509ExtensionUtil;
}

@end

void LibOrgBouncycastleX509ExtensionX509ExtensionUtil_init(LibOrgBouncycastleX509ExtensionX509ExtensionUtil *self) {
  NSObject_init(self);
}

LibOrgBouncycastleX509ExtensionX509ExtensionUtil *new_LibOrgBouncycastleX509ExtensionX509ExtensionUtil_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleX509ExtensionX509ExtensionUtil, init)
}

LibOrgBouncycastleX509ExtensionX509ExtensionUtil *create_LibOrgBouncycastleX509ExtensionX509ExtensionUtil_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleX509ExtensionX509ExtensionUtil, init)
}

LibOrgBouncycastleAsn1ASN1Primitive *LibOrgBouncycastleX509ExtensionX509ExtensionUtil_fromExtensionValueWithByteArray_(IOSByteArray *encodedValue) {
  LibOrgBouncycastleX509ExtensionX509ExtensionUtil_initialize();
  LibOrgBouncycastleAsn1ASN1OctetString *octs = (LibOrgBouncycastleAsn1ASN1OctetString *) cast_chk(LibOrgBouncycastleAsn1ASN1Primitive_fromByteArrayWithByteArray_(encodedValue), [LibOrgBouncycastleAsn1ASN1OctetString class]);
  return LibOrgBouncycastleAsn1ASN1Primitive_fromByteArrayWithByteArray_([((LibOrgBouncycastleAsn1ASN1OctetString *) nil_chk(octs)) getOctets]);
}

id<JavaUtilCollection> LibOrgBouncycastleX509ExtensionX509ExtensionUtil_getIssuerAlternativeNamesWithJavaSecurityCertX509Certificate_(JavaSecurityCertX509Certificate *cert) {
  LibOrgBouncycastleX509ExtensionX509ExtensionUtil_initialize();
  IOSByteArray *extVal = [((JavaSecurityCertX509Certificate *) nil_chk(cert)) getExtensionValueWithNSString:[((LibOrgBouncycastleAsn1ASN1ObjectIdentifier *) nil_chk(JreLoadStatic(LibOrgBouncycastleAsn1X509Extension, issuerAlternativeName))) getId]];
  return LibOrgBouncycastleX509ExtensionX509ExtensionUtil_getAlternativeNamesWithByteArray_(extVal);
}

id<JavaUtilCollection> LibOrgBouncycastleX509ExtensionX509ExtensionUtil_getSubjectAlternativeNamesWithJavaSecurityCertX509Certificate_(JavaSecurityCertX509Certificate *cert) {
  LibOrgBouncycastleX509ExtensionX509ExtensionUtil_initialize();
  IOSByteArray *extVal = [((JavaSecurityCertX509Certificate *) nil_chk(cert)) getExtensionValueWithNSString:[((LibOrgBouncycastleAsn1ASN1ObjectIdentifier *) nil_chk(JreLoadStatic(LibOrgBouncycastleAsn1X509Extension, subjectAlternativeName))) getId]];
  return LibOrgBouncycastleX509ExtensionX509ExtensionUtil_getAlternativeNamesWithByteArray_(extVal);
}

id<JavaUtilCollection> LibOrgBouncycastleX509ExtensionX509ExtensionUtil_getAlternativeNamesWithByteArray_(IOSByteArray *extVal) {
  LibOrgBouncycastleX509ExtensionX509ExtensionUtil_initialize();
  if (extVal == nil) {
    return JreLoadStatic(JavaUtilCollections, EMPTY_LIST);
  }
  @try {
    id<JavaUtilCollection> temp = new_JavaUtilArrayList_init();
    id<JavaUtilEnumeration> it = [((LibOrgBouncycastleAsn1ASN1Sequence *) nil_chk(LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithId_(LibOrgBouncycastleX509ExtensionX509ExtensionUtil_fromExtensionValueWithByteArray_(extVal)))) getObjects];
    while ([((id<JavaUtilEnumeration>) nil_chk(it)) hasMoreElements]) {
      LibOrgBouncycastleAsn1X509GeneralName *genName = LibOrgBouncycastleAsn1X509GeneralName_getInstanceWithId_([it nextElement]);
      id<JavaUtilList> list = new_JavaUtilArrayList_init();
      [list addWithId:LibOrgBouncycastleUtilIntegers_valueOfWithInt_([((LibOrgBouncycastleAsn1X509GeneralName *) nil_chk(genName)) getTagNo])];
      switch ([genName getTagNo]) {
        case LibOrgBouncycastleAsn1X509GeneralName_ediPartyName:
        case LibOrgBouncycastleAsn1X509GeneralName_x400Address:
        case LibOrgBouncycastleAsn1X509GeneralName_otherName:
        [list addWithId:[((id<LibOrgBouncycastleAsn1ASN1Encodable>) nil_chk([genName getName])) toASN1Primitive]];
        break;
        case LibOrgBouncycastleAsn1X509GeneralName_directoryName:
        [list addWithId:[((LibOrgBouncycastleAsn1X500X500Name *) nil_chk(LibOrgBouncycastleAsn1X500X500Name_getInstanceWithId_([genName getName]))) description]];
        break;
        case LibOrgBouncycastleAsn1X509GeneralName_dNSName:
        case LibOrgBouncycastleAsn1X509GeneralName_rfc822Name:
        case LibOrgBouncycastleAsn1X509GeneralName_uniformResourceIdentifier:
        [list addWithId:[((id<LibOrgBouncycastleAsn1ASN1String>) nil_chk(((id<LibOrgBouncycastleAsn1ASN1String>) cast_check([genName getName], LibOrgBouncycastleAsn1ASN1String_class_())))) getString]];
        break;
        case LibOrgBouncycastleAsn1X509GeneralName_registeredID:
        [list addWithId:[((LibOrgBouncycastleAsn1ASN1ObjectIdentifier *) nil_chk(LibOrgBouncycastleAsn1ASN1ObjectIdentifier_getInstanceWithId_([genName getName]))) getId]];
        break;
        case LibOrgBouncycastleAsn1X509GeneralName_iPAddress:
        [list addWithId:[((LibOrgBouncycastleAsn1ASN1OctetString *) nil_chk(LibOrgBouncycastleAsn1ASN1OctetString_getInstanceWithId_([genName getName]))) getOctets]];
        break;
        default:
        @throw new_JavaIoIOException_initWithNSString_(JreStrcat("$I", @"Bad tag number: ", [genName getTagNo]));
      }
      [temp addWithId:list];
    }
    return JavaUtilCollections_unmodifiableCollectionWithJavaUtilCollection_(temp);
  }
  @catch (JavaLangException *e) {
    @throw new_JavaSecurityCertCertificateParsingException_initWithNSString_([e getMessage]);
  }
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleX509ExtensionX509ExtensionUtil)
