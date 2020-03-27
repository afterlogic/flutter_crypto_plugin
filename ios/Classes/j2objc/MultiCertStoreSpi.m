//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jce/provider/MultiCertStoreSpi.java
//

#include "J2ObjC_source.h"
#include "MultiCertStoreParameters.h"
#include "MultiCertStoreSpi.h"
#include "java/security/InvalidAlgorithmParameterException.h"
#include "java/security/cert/CRLSelector.h"
#include "java/security/cert/CertSelector.h"
#include "java/security/cert/CertStore.h"
#include "java/security/cert/CertStoreParameters.h"
#include "java/security/cert/CertStoreSpi.h"
#include "java/util/ArrayList.h"
#include "java/util/Collection.h"
#include "java/util/Collections.h"
#include "java/util/Iterator.h"
#include "java/util/List.h"

@interface LibOrgBouncycastleJceProviderMultiCertStoreSpi () {
 @public
  LibOrgBouncycastleJceMultiCertStoreParameters *params_;
}

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleJceProviderMultiCertStoreSpi, params_, LibOrgBouncycastleJceMultiCertStoreParameters *)

@implementation LibOrgBouncycastleJceProviderMultiCertStoreSpi

- (instancetype)initWithJavaSecurityCertCertStoreParameters:(id<JavaSecurityCertCertStoreParameters>)params {
  LibOrgBouncycastleJceProviderMultiCertStoreSpi_initWithJavaSecurityCertCertStoreParameters_(self, params);
  return self;
}

- (id<JavaUtilCollection>)engineGetCertificatesWithJavaSecurityCertCertSelector:(id<JavaSecurityCertCertSelector>)certSelector {
  jboolean searchAllStores = [((LibOrgBouncycastleJceMultiCertStoreParameters *) nil_chk(params_)) getSearchAllStores];
  id<JavaUtilIterator> iter = [((id<JavaUtilCollection>) nil_chk([((LibOrgBouncycastleJceMultiCertStoreParameters *) nil_chk(params_)) getCertStores])) iterator];
  id<JavaUtilList> allCerts = searchAllStores ? new_JavaUtilArrayList_init() : JreLoadStatic(JavaUtilCollections, EMPTY_LIST);
  while ([((id<JavaUtilIterator>) nil_chk(iter)) hasNext]) {
    JavaSecurityCertCertStore *store = (JavaSecurityCertCertStore *) cast_chk([iter next], [JavaSecurityCertCertStore class]);
    id<JavaUtilCollection> certs = [((JavaSecurityCertCertStore *) nil_chk(store)) getCertificatesWithJavaSecurityCertCertSelector:certSelector];
    if (searchAllStores) {
      [allCerts addAllWithJavaUtilCollection:certs];
    }
    else if (![((id<JavaUtilCollection>) nil_chk(certs)) isEmpty]) {
      return certs;
    }
  }
  return allCerts;
}

- (id<JavaUtilCollection>)engineGetCRLsWithJavaSecurityCertCRLSelector:(id<JavaSecurityCertCRLSelector>)crlSelector {
  jboolean searchAllStores = [((LibOrgBouncycastleJceMultiCertStoreParameters *) nil_chk(params_)) getSearchAllStores];
  id<JavaUtilIterator> iter = [((id<JavaUtilCollection>) nil_chk([((LibOrgBouncycastleJceMultiCertStoreParameters *) nil_chk(params_)) getCertStores])) iterator];
  id<JavaUtilList> allCRLs = searchAllStores ? new_JavaUtilArrayList_init() : JreLoadStatic(JavaUtilCollections, EMPTY_LIST);
  while ([((id<JavaUtilIterator>) nil_chk(iter)) hasNext]) {
    JavaSecurityCertCertStore *store = (JavaSecurityCertCertStore *) cast_chk([iter next], [JavaSecurityCertCertStore class]);
    id<JavaUtilCollection> crls = [((JavaSecurityCertCertStore *) nil_chk(store)) getCRLsWithJavaSecurityCertCRLSelector:crlSelector];
    if (searchAllStores) {
      [allCRLs addAllWithJavaUtilCollection:crls];
    }
    else if (![((id<JavaUtilCollection>) nil_chk(crls)) isEmpty]) {
      return crls;
    }
  }
  return allCRLs;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, 1, -1, -1, -1 },
    { NULL, "LJavaUtilCollection;", 0x1, 2, 3, 4, -1, -1, -1 },
    { NULL, "LJavaUtilCollection;", 0x1, 5, 6, 4, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithJavaSecurityCertCertStoreParameters:);
  methods[1].selector = @selector(engineGetCertificatesWithJavaSecurityCertCertSelector:);
  methods[2].selector = @selector(engineGetCRLsWithJavaSecurityCertCRLSelector:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "params_", "LLibOrgBouncycastleJceMultiCertStoreParameters;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LJavaSecurityCertCertStoreParameters;", "LJavaSecurityInvalidAlgorithmParameterException;", "engineGetCertificates", "LJavaSecurityCertCertSelector;", "LJavaSecurityCertCertStoreException;", "engineGetCRLs", "LJavaSecurityCertCRLSelector;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJceProviderMultiCertStoreSpi = { "MultiCertStoreSpi", "lib.org.bouncycastle.jce.provider", ptrTable, methods, fields, 7, 0x1, 3, 1, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJceProviderMultiCertStoreSpi;
}

@end

void LibOrgBouncycastleJceProviderMultiCertStoreSpi_initWithJavaSecurityCertCertStoreParameters_(LibOrgBouncycastleJceProviderMultiCertStoreSpi *self, id<JavaSecurityCertCertStoreParameters> params) {
  JavaSecurityCertCertStoreSpi_initWithJavaSecurityCertCertStoreParameters_(self, params);
  if (!([params isKindOfClass:[LibOrgBouncycastleJceMultiCertStoreParameters class]])) {
    @throw new_JavaSecurityInvalidAlgorithmParameterException_initWithNSString_(JreStrcat("$$", @"lib.org.bouncycastle.jce.provider.MultiCertStoreSpi: parameter must be a MultiCertStoreParameters object\n", [((id<JavaSecurityCertCertStoreParameters>) nil_chk(params)) description]));
  }
  self->params_ = (LibOrgBouncycastleJceMultiCertStoreParameters *) cast_chk(params, [LibOrgBouncycastleJceMultiCertStoreParameters class]);
}

LibOrgBouncycastleJceProviderMultiCertStoreSpi *new_LibOrgBouncycastleJceProviderMultiCertStoreSpi_initWithJavaSecurityCertCertStoreParameters_(id<JavaSecurityCertCertStoreParameters> params) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJceProviderMultiCertStoreSpi, initWithJavaSecurityCertCertStoreParameters_, params)
}

LibOrgBouncycastleJceProviderMultiCertStoreSpi *create_LibOrgBouncycastleJceProviderMultiCertStoreSpi_initWithJavaSecurityCertCertStoreParameters_(id<JavaSecurityCertCertStoreParameters> params) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJceProviderMultiCertStoreSpi, initWithJavaSecurityCertCertStoreParameters_, params)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJceProviderMultiCertStoreSpi)