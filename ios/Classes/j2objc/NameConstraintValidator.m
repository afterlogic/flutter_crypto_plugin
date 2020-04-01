//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/x509/NameConstraintValidator.java
//

#include "J2ObjC_source.h"
#include "NameConstraintValidator.h"

@interface LibOrgBouncycastleAsn1X509NameConstraintValidator : NSObject

@end

@implementation LibOrgBouncycastleAsn1X509NameConstraintValidator

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, "V", 0x401, 0, 1, 2, -1, -1, -1 },
    { NULL, "V", 0x401, 3, 1, 2, -1, -1, -1 },
    { NULL, "V", 0x401, 4, 5, -1, -1, -1, -1 },
    { NULL, "V", 0x401, 4, 6, -1, -1, -1, -1 },
    { NULL, "V", 0x401, 7, 8, -1, -1, -1, -1 },
    { NULL, "V", 0x401, 9, 5, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(checkPermittedWithLibOrgBouncycastleAsn1X509GeneralName:);
  methods[1].selector = @selector(checkExcludedWithLibOrgBouncycastleAsn1X509GeneralName:);
  methods[2].selector = @selector(intersectPermittedSubtreeWithLibOrgBouncycastleAsn1X509GeneralSubtree:);
  methods[3].selector = @selector(intersectPermittedSubtreeWithLibOrgBouncycastleAsn1X509GeneralSubtreeArray:);
  methods[4].selector = @selector(intersectEmptyPermittedSubtreeWithInt:);
  methods[5].selector = @selector(addExcludedSubtreeWithLibOrgBouncycastleAsn1X509GeneralSubtree:);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "checkPermitted", "LLibOrgBouncycastleAsn1X509GeneralName;", "LLibOrgBouncycastleAsn1X509NameConstraintValidatorException;", "checkExcluded", "intersectPermittedSubtree", "LLibOrgBouncycastleAsn1X509GeneralSubtree;", "[LLibOrgBouncycastleAsn1X509GeneralSubtree;", "intersectEmptyPermittedSubtree", "I", "addExcludedSubtree" };
  static const J2ObjcClassInfo _LibOrgBouncycastleAsn1X509NameConstraintValidator = { "NameConstraintValidator", "lib.org.bouncycastle.asn1.x509", ptrTable, methods, NULL, 7, 0x609, 6, 0, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleAsn1X509NameConstraintValidator;
}

@end

J2OBJC_INTERFACE_TYPE_LITERAL_SOURCE(LibOrgBouncycastleAsn1X509NameConstraintValidator)