//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jce/provider/X509StoreCRLCollection.java
//

#include "CollectionStore.h"
#include "J2ObjC_source.h"
#include "Selector.h"
#include "X509CollectionStoreParameters.h"
#include "X509StoreCRLCollection.h"
#include "X509StoreParameters.h"
#include "X509StoreSpi.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/util/Collection.h"

@interface LibOrgBouncycastleJceProviderX509StoreCRLCollection () {
 @public
  LibOrgBouncycastleUtilCollectionStore *_store_;
}

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleJceProviderX509StoreCRLCollection, _store_, LibOrgBouncycastleUtilCollectionStore *)

@implementation LibOrgBouncycastleJceProviderX509StoreCRLCollection

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJceProviderX509StoreCRLCollection_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (void)engineInitWithLibOrgBouncycastleX509X509StoreParameters:(id<LibOrgBouncycastleX509X509StoreParameters>)params {
  if (!([params isKindOfClass:[LibOrgBouncycastleX509X509CollectionStoreParameters class]])) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_([((id<LibOrgBouncycastleX509X509StoreParameters>) nil_chk(params)) description]);
  }
  _store_ = new_LibOrgBouncycastleUtilCollectionStore_initWithJavaUtilCollection_([((LibOrgBouncycastleX509X509CollectionStoreParameters *) nil_chk(((LibOrgBouncycastleX509X509CollectionStoreParameters *) cast_chk(params, [LibOrgBouncycastleX509X509CollectionStoreParameters class])))) getCollection]);
}

- (id<JavaUtilCollection>)engineGetMatchesWithLibOrgBouncycastleUtilSelector:(id<LibOrgBouncycastleUtilSelector>)selector {
  return [((LibOrgBouncycastleUtilCollectionStore *) nil_chk(_store_)) getMatchesWithLibOrgBouncycastleUtilSelector:selector];
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 0, 1, -1, -1, -1, -1 },
    { NULL, "LJavaUtilCollection;", 0x1, 2, 3, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(engineInitWithLibOrgBouncycastleX509X509StoreParameters:);
  methods[2].selector = @selector(engineGetMatchesWithLibOrgBouncycastleUtilSelector:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "_store_", "LLibOrgBouncycastleUtilCollectionStore;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "engineInit", "LLibOrgBouncycastleX509X509StoreParameters;", "engineGetMatches", "LLibOrgBouncycastleUtilSelector;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJceProviderX509StoreCRLCollection = { "X509StoreCRLCollection", "lib.org.bouncycastle.jce.provider", ptrTable, methods, fields, 7, 0x1, 3, 1, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJceProviderX509StoreCRLCollection;
}

@end

void LibOrgBouncycastleJceProviderX509StoreCRLCollection_init(LibOrgBouncycastleJceProviderX509StoreCRLCollection *self) {
  LibOrgBouncycastleX509X509StoreSpi_init(self);
}

LibOrgBouncycastleJceProviderX509StoreCRLCollection *new_LibOrgBouncycastleJceProviderX509StoreCRLCollection_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJceProviderX509StoreCRLCollection, init)
}

LibOrgBouncycastleJceProviderX509StoreCRLCollection *create_LibOrgBouncycastleJceProviderX509StoreCRLCollection_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJceProviderX509StoreCRLCollection, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJceProviderX509StoreCRLCollection)