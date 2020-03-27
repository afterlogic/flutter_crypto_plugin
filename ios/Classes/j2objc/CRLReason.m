//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/x509/CRLReason.java
//

#include "ASN1Enumerated.h"
#include "ASN1Object.h"
#include "ASN1Primitive.h"
#include "CRLReason.h"
#include "IOSClass.h"
#include "IOSObjectArray.h"
#include "Integers.h"
#include "J2ObjC_source.h"
#include "java/lang/Integer.h"
#include "java/math/BigInteger.h"
#include "java/util/Hashtable.h"

@interface LibOrgBouncycastleAsn1X509CRLReason () {
 @public
  LibOrgBouncycastleAsn1ASN1Enumerated *value_;
}

- (instancetype)initWithInt:(jint)reason;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1X509CRLReason, value_, LibOrgBouncycastleAsn1ASN1Enumerated *)

inline IOSObjectArray *LibOrgBouncycastleAsn1X509CRLReason_get_reasonString(void);
static IOSObjectArray *LibOrgBouncycastleAsn1X509CRLReason_reasonString;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleAsn1X509CRLReason, reasonString, IOSObjectArray *)

inline JavaUtilHashtable *LibOrgBouncycastleAsn1X509CRLReason_get_table(void);
static JavaUtilHashtable *LibOrgBouncycastleAsn1X509CRLReason_table;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleAsn1X509CRLReason, table, JavaUtilHashtable *)

__attribute__((unused)) static void LibOrgBouncycastleAsn1X509CRLReason_initWithInt_(LibOrgBouncycastleAsn1X509CRLReason *self, jint reason);

__attribute__((unused)) static LibOrgBouncycastleAsn1X509CRLReason *new_LibOrgBouncycastleAsn1X509CRLReason_initWithInt_(jint reason) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleAsn1X509CRLReason *create_LibOrgBouncycastleAsn1X509CRLReason_initWithInt_(jint reason);

J2OBJC_INITIALIZED_DEFN(LibOrgBouncycastleAsn1X509CRLReason)

@implementation LibOrgBouncycastleAsn1X509CRLReason

+ (jint)UNSPECIFIED {
  return LibOrgBouncycastleAsn1X509CRLReason_UNSPECIFIED;
}

+ (jint)KEY_COMPROMISE {
  return LibOrgBouncycastleAsn1X509CRLReason_KEY_COMPROMISE;
}

+ (jint)CA_COMPROMISE {
  return LibOrgBouncycastleAsn1X509CRLReason_CA_COMPROMISE;
}

+ (jint)AFFILIATION_CHANGED {
  return LibOrgBouncycastleAsn1X509CRLReason_AFFILIATION_CHANGED;
}

+ (jint)SUPERSEDED {
  return LibOrgBouncycastleAsn1X509CRLReason_SUPERSEDED;
}

+ (jint)CESSATION_OF_OPERATION {
  return LibOrgBouncycastleAsn1X509CRLReason_CESSATION_OF_OPERATION;
}

+ (jint)CERTIFICATE_HOLD {
  return LibOrgBouncycastleAsn1X509CRLReason_CERTIFICATE_HOLD;
}

+ (jint)REMOVE_FROM_CRL {
  return LibOrgBouncycastleAsn1X509CRLReason_REMOVE_FROM_CRL;
}

+ (jint)PRIVILEGE_WITHDRAWN {
  return LibOrgBouncycastleAsn1X509CRLReason_PRIVILEGE_WITHDRAWN;
}

+ (jint)AA_COMPROMISE {
  return LibOrgBouncycastleAsn1X509CRLReason_AA_COMPROMISE;
}

+ (jint)unspecified {
  return LibOrgBouncycastleAsn1X509CRLReason_unspecified;
}

+ (jint)keyCompromise {
  return LibOrgBouncycastleAsn1X509CRLReason_keyCompromise;
}

+ (jint)cACompromise {
  return LibOrgBouncycastleAsn1X509CRLReason_cACompromise;
}

+ (jint)affiliationChanged {
  return LibOrgBouncycastleAsn1X509CRLReason_affiliationChanged;
}

+ (jint)superseded {
  return LibOrgBouncycastleAsn1X509CRLReason_superseded;
}

+ (jint)cessationOfOperation {
  return LibOrgBouncycastleAsn1X509CRLReason_cessationOfOperation;
}

+ (jint)certificateHold {
  return LibOrgBouncycastleAsn1X509CRLReason_certificateHold;
}

+ (jint)removeFromCRL {
  return LibOrgBouncycastleAsn1X509CRLReason_removeFromCRL;
}

+ (jint)privilegeWithdrawn {
  return LibOrgBouncycastleAsn1X509CRLReason_privilegeWithdrawn;
}

+ (jint)aACompromise {
  return LibOrgBouncycastleAsn1X509CRLReason_aACompromise;
}

+ (LibOrgBouncycastleAsn1X509CRLReason *)getInstanceWithId:(id)o {
  return LibOrgBouncycastleAsn1X509CRLReason_getInstanceWithId_(o);
}

- (instancetype)initWithInt:(jint)reason {
  LibOrgBouncycastleAsn1X509CRLReason_initWithInt_(self, reason);
  return self;
}

- (NSString *)description {
  NSString *str;
  jint reason = [((JavaMathBigInteger *) nil_chk([self getValue])) intValue];
  if (reason < 0 || reason > 10) {
    str = @"invalid";
  }
  else {
    str = IOSObjectArray_Get(nil_chk(LibOrgBouncycastleAsn1X509CRLReason_reasonString), reason);
  }
  return JreStrcat("$$", @"CRLReason: ", str);
}

- (JavaMathBigInteger *)getValue {
  return [((LibOrgBouncycastleAsn1ASN1Enumerated *) nil_chk(value_)) getValue];
}

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive {
  return value_;
}

+ (LibOrgBouncycastleAsn1X509CRLReason *)lookupWithInt:(jint)value {
  return LibOrgBouncycastleAsn1X509CRLReason_lookupWithInt_(value);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, "LLibOrgBouncycastleAsn1X509CRLReason;", 0x9, 0, 1, -1, -1, -1, -1 },
    { NULL, NULL, 0x2, -1, 2, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x1, 3, -1, -1, -1, -1, -1 },
    { NULL, "LJavaMathBigInteger;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1X509CRLReason;", 0x9, 4, 2, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(getInstanceWithId:);
  methods[1].selector = @selector(initWithInt:);
  methods[2].selector = @selector(description);
  methods[3].selector = @selector(getValue);
  methods[4].selector = @selector(toASN1Primitive);
  methods[5].selector = @selector(lookupWithInt:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "UNSPECIFIED", "I", .constantValue.asInt = LibOrgBouncycastleAsn1X509CRLReason_UNSPECIFIED, 0x19, -1, -1, -1, -1 },
    { "KEY_COMPROMISE", "I", .constantValue.asInt = LibOrgBouncycastleAsn1X509CRLReason_KEY_COMPROMISE, 0x19, -1, -1, -1, -1 },
    { "CA_COMPROMISE", "I", .constantValue.asInt = LibOrgBouncycastleAsn1X509CRLReason_CA_COMPROMISE, 0x19, -1, -1, -1, -1 },
    { "AFFILIATION_CHANGED", "I", .constantValue.asInt = LibOrgBouncycastleAsn1X509CRLReason_AFFILIATION_CHANGED, 0x19, -1, -1, -1, -1 },
    { "SUPERSEDED", "I", .constantValue.asInt = LibOrgBouncycastleAsn1X509CRLReason_SUPERSEDED, 0x19, -1, -1, -1, -1 },
    { "CESSATION_OF_OPERATION", "I", .constantValue.asInt = LibOrgBouncycastleAsn1X509CRLReason_CESSATION_OF_OPERATION, 0x19, -1, -1, -1, -1 },
    { "CERTIFICATE_HOLD", "I", .constantValue.asInt = LibOrgBouncycastleAsn1X509CRLReason_CERTIFICATE_HOLD, 0x19, -1, -1, -1, -1 },
    { "REMOVE_FROM_CRL", "I", .constantValue.asInt = LibOrgBouncycastleAsn1X509CRLReason_REMOVE_FROM_CRL, 0x19, -1, -1, -1, -1 },
    { "PRIVILEGE_WITHDRAWN", "I", .constantValue.asInt = LibOrgBouncycastleAsn1X509CRLReason_PRIVILEGE_WITHDRAWN, 0x19, -1, -1, -1, -1 },
    { "AA_COMPROMISE", "I", .constantValue.asInt = LibOrgBouncycastleAsn1X509CRLReason_AA_COMPROMISE, 0x19, -1, -1, -1, -1 },
    { "unspecified", "I", .constantValue.asInt = LibOrgBouncycastleAsn1X509CRLReason_unspecified, 0x19, -1, -1, -1, -1 },
    { "keyCompromise", "I", .constantValue.asInt = LibOrgBouncycastleAsn1X509CRLReason_keyCompromise, 0x19, -1, -1, -1, -1 },
    { "cACompromise", "I", .constantValue.asInt = LibOrgBouncycastleAsn1X509CRLReason_cACompromise, 0x19, -1, -1, -1, -1 },
    { "affiliationChanged", "I", .constantValue.asInt = LibOrgBouncycastleAsn1X509CRLReason_affiliationChanged, 0x19, -1, -1, -1, -1 },
    { "superseded", "I", .constantValue.asInt = LibOrgBouncycastleAsn1X509CRLReason_superseded, 0x19, -1, -1, -1, -1 },
    { "cessationOfOperation", "I", .constantValue.asInt = LibOrgBouncycastleAsn1X509CRLReason_cessationOfOperation, 0x19, -1, -1, -1, -1 },
    { "certificateHold", "I", .constantValue.asInt = LibOrgBouncycastleAsn1X509CRLReason_certificateHold, 0x19, -1, -1, -1, -1 },
    { "removeFromCRL", "I", .constantValue.asInt = LibOrgBouncycastleAsn1X509CRLReason_removeFromCRL, 0x19, -1, -1, -1, -1 },
    { "privilegeWithdrawn", "I", .constantValue.asInt = LibOrgBouncycastleAsn1X509CRLReason_privilegeWithdrawn, 0x19, -1, -1, -1, -1 },
    { "aACompromise", "I", .constantValue.asInt = LibOrgBouncycastleAsn1X509CRLReason_aACompromise, 0x19, -1, -1, -1, -1 },
    { "reasonString", "[LNSString;", .constantValue.asLong = 0, 0x1a, -1, 5, -1, -1 },
    { "table", "LJavaUtilHashtable;", .constantValue.asLong = 0, 0x1a, -1, 6, -1, -1 },
    { "value_", "LLibOrgBouncycastleAsn1ASN1Enumerated;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "getInstance", "LNSObject;", "I", "toString", "lookup", &LibOrgBouncycastleAsn1X509CRLReason_reasonString, &LibOrgBouncycastleAsn1X509CRLReason_table };
  static const J2ObjcClassInfo _LibOrgBouncycastleAsn1X509CRLReason = { "CRLReason", "lib.org.bouncycastle.asn1.x509", ptrTable, methods, fields, 7, 0x1, 6, 23, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleAsn1X509CRLReason;
}

+ (void)initialize {
  if (self == [LibOrgBouncycastleAsn1X509CRLReason class]) {
    LibOrgBouncycastleAsn1X509CRLReason_reasonString = [IOSObjectArray newArrayWithObjects:(id[]){ @"unspecified", @"keyCompromise", @"cACompromise", @"affiliationChanged", @"superseded", @"cessationOfOperation", @"certificateHold", @"unknown", @"removeFromCRL", @"privilegeWithdrawn", @"aACompromise" } count:11 type:NSString_class_()];
    LibOrgBouncycastleAsn1X509CRLReason_table = new_JavaUtilHashtable_init();
    J2OBJC_SET_INITIALIZED(LibOrgBouncycastleAsn1X509CRLReason)
  }
}

@end

LibOrgBouncycastleAsn1X509CRLReason *LibOrgBouncycastleAsn1X509CRLReason_getInstanceWithId_(id o) {
  LibOrgBouncycastleAsn1X509CRLReason_initialize();
  if ([o isKindOfClass:[LibOrgBouncycastleAsn1X509CRLReason class]]) {
    return (LibOrgBouncycastleAsn1X509CRLReason *) o;
  }
  else if (o != nil) {
    return LibOrgBouncycastleAsn1X509CRLReason_lookupWithInt_([((JavaMathBigInteger *) nil_chk([((LibOrgBouncycastleAsn1ASN1Enumerated *) nil_chk(LibOrgBouncycastleAsn1ASN1Enumerated_getInstanceWithId_(o))) getValue])) intValue]);
  }
  return nil;
}

void LibOrgBouncycastleAsn1X509CRLReason_initWithInt_(LibOrgBouncycastleAsn1X509CRLReason *self, jint reason) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->value_ = new_LibOrgBouncycastleAsn1ASN1Enumerated_initWithInt_(reason);
}

LibOrgBouncycastleAsn1X509CRLReason *new_LibOrgBouncycastleAsn1X509CRLReason_initWithInt_(jint reason) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1X509CRLReason, initWithInt_, reason)
}

LibOrgBouncycastleAsn1X509CRLReason *create_LibOrgBouncycastleAsn1X509CRLReason_initWithInt_(jint reason) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1X509CRLReason, initWithInt_, reason)
}

LibOrgBouncycastleAsn1X509CRLReason *LibOrgBouncycastleAsn1X509CRLReason_lookupWithInt_(jint value) {
  LibOrgBouncycastleAsn1X509CRLReason_initialize();
  JavaLangInteger *idx = LibOrgBouncycastleUtilIntegers_valueOfWithInt_(value);
  if (![((JavaUtilHashtable *) nil_chk(LibOrgBouncycastleAsn1X509CRLReason_table)) containsKeyWithId:idx]) {
    (void) [LibOrgBouncycastleAsn1X509CRLReason_table putWithId:idx withId:new_LibOrgBouncycastleAsn1X509CRLReason_initWithInt_(value)];
  }
  return (LibOrgBouncycastleAsn1X509CRLReason *) cast_chk([LibOrgBouncycastleAsn1X509CRLReason_table getWithId:idx], [LibOrgBouncycastleAsn1X509CRLReason class]);
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleAsn1X509CRLReason)