//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/isismtt/x509/ProcurationSyntax.java
//

#include "ASN1Encodable.h"
#include "ASN1EncodableVector.h"
#include "ASN1Object.h"
#include "ASN1Primitive.h"
#include "ASN1Sequence.h"
#include "ASN1TaggedObject.h"
#include "DERPrintableString.h"
#include "DERSequence.h"
#include "DERTaggedObject.h"
#include "DirectoryString.h"
#include "GeneralName.h"
#include "IOSClass.h"
#include "IssuerSerial.h"
#include "J2ObjC_source.h"
#include "ProcurationSyntax.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/util/Enumeration.h"

@interface LibOrgBouncycastleAsn1IsismttX509ProcurationSyntax () {
 @public
  NSString *country_;
  LibOrgBouncycastleAsn1X500DirectoryString *typeOfSubstitution_;
  LibOrgBouncycastleAsn1X509GeneralName *thirdPerson_;
  LibOrgBouncycastleAsn1X509IssuerSerial *certRef_;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1IsismttX509ProcurationSyntax, country_, NSString *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1IsismttX509ProcurationSyntax, typeOfSubstitution_, LibOrgBouncycastleAsn1X500DirectoryString *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1IsismttX509ProcurationSyntax, thirdPerson_, LibOrgBouncycastleAsn1X509GeneralName *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1IsismttX509ProcurationSyntax, certRef_, LibOrgBouncycastleAsn1X509IssuerSerial *)

__attribute__((unused)) static void LibOrgBouncycastleAsn1IsismttX509ProcurationSyntax_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1IsismttX509ProcurationSyntax *self, LibOrgBouncycastleAsn1ASN1Sequence *seq);

__attribute__((unused)) static LibOrgBouncycastleAsn1IsismttX509ProcurationSyntax *new_LibOrgBouncycastleAsn1IsismttX509ProcurationSyntax_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleAsn1IsismttX509ProcurationSyntax *create_LibOrgBouncycastleAsn1IsismttX509ProcurationSyntax_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq);

@implementation LibOrgBouncycastleAsn1IsismttX509ProcurationSyntax

+ (LibOrgBouncycastleAsn1IsismttX509ProcurationSyntax *)getInstanceWithId:(id)obj {
  return LibOrgBouncycastleAsn1IsismttX509ProcurationSyntax_getInstanceWithId_(obj);
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq {
  LibOrgBouncycastleAsn1IsismttX509ProcurationSyntax_initWithLibOrgBouncycastleAsn1ASN1Sequence_(self, seq);
  return self;
}

- (instancetype)initWithNSString:(NSString *)country
withLibOrgBouncycastleAsn1X500DirectoryString:(LibOrgBouncycastleAsn1X500DirectoryString *)typeOfSubstitution
withLibOrgBouncycastleAsn1X509IssuerSerial:(LibOrgBouncycastleAsn1X509IssuerSerial *)certRef {
  LibOrgBouncycastleAsn1IsismttX509ProcurationSyntax_initWithNSString_withLibOrgBouncycastleAsn1X500DirectoryString_withLibOrgBouncycastleAsn1X509IssuerSerial_(self, country, typeOfSubstitution, certRef);
  return self;
}

- (instancetype)initWithNSString:(NSString *)country
withLibOrgBouncycastleAsn1X500DirectoryString:(LibOrgBouncycastleAsn1X500DirectoryString *)typeOfSubstitution
withLibOrgBouncycastleAsn1X509GeneralName:(LibOrgBouncycastleAsn1X509GeneralName *)thirdPerson {
  LibOrgBouncycastleAsn1IsismttX509ProcurationSyntax_initWithNSString_withLibOrgBouncycastleAsn1X500DirectoryString_withLibOrgBouncycastleAsn1X509GeneralName_(self, country, typeOfSubstitution, thirdPerson);
  return self;
}

- (NSString *)getCountry {
  return country_;
}

- (LibOrgBouncycastleAsn1X500DirectoryString *)getTypeOfSubstitution {
  return typeOfSubstitution_;
}

- (LibOrgBouncycastleAsn1X509GeneralName *)getThirdPerson {
  return thirdPerson_;
}

- (LibOrgBouncycastleAsn1X509IssuerSerial *)getCertRef {
  return certRef_;
}

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive {
  LibOrgBouncycastleAsn1ASN1EncodableVector *vec = new_LibOrgBouncycastleAsn1ASN1EncodableVector_init();
  if (country_ != nil) {
    [vec addWithLibOrgBouncycastleAsn1ASN1Encodable:new_LibOrgBouncycastleAsn1DERTaggedObject_initWithBoolean_withInt_withLibOrgBouncycastleAsn1ASN1Encodable_(true, 1, new_LibOrgBouncycastleAsn1DERPrintableString_initWithNSString_withBoolean_(country_, true))];
  }
  if (typeOfSubstitution_ != nil) {
    [vec addWithLibOrgBouncycastleAsn1ASN1Encodable:new_LibOrgBouncycastleAsn1DERTaggedObject_initWithBoolean_withInt_withLibOrgBouncycastleAsn1ASN1Encodable_(true, 2, typeOfSubstitution_)];
  }
  if (thirdPerson_ != nil) {
    [vec addWithLibOrgBouncycastleAsn1ASN1Encodable:new_LibOrgBouncycastleAsn1DERTaggedObject_initWithBoolean_withInt_withLibOrgBouncycastleAsn1ASN1Encodable_(true, 3, thirdPerson_)];
  }
  else {
    [vec addWithLibOrgBouncycastleAsn1ASN1Encodable:new_LibOrgBouncycastleAsn1DERTaggedObject_initWithBoolean_withInt_withLibOrgBouncycastleAsn1ASN1Encodable_(true, 3, certRef_)];
  }
  return new_LibOrgBouncycastleAsn1DERSequence_initWithLibOrgBouncycastleAsn1ASN1EncodableVector_(vec);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, "LLibOrgBouncycastleAsn1IsismttX509ProcurationSyntax;", 0x9, 0, 1, -1, -1, -1, -1 },
    { NULL, NULL, 0x2, -1, 2, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 3, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 4, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1X500DirectoryString;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1X509GeneralName;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1X509IssuerSerial;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(getInstanceWithId:);
  methods[1].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1Sequence:);
  methods[2].selector = @selector(initWithNSString:withLibOrgBouncycastleAsn1X500DirectoryString:withLibOrgBouncycastleAsn1X509IssuerSerial:);
  methods[3].selector = @selector(initWithNSString:withLibOrgBouncycastleAsn1X500DirectoryString:withLibOrgBouncycastleAsn1X509GeneralName:);
  methods[4].selector = @selector(getCountry);
  methods[5].selector = @selector(getTypeOfSubstitution);
  methods[6].selector = @selector(getThirdPerson);
  methods[7].selector = @selector(getCertRef);
  methods[8].selector = @selector(toASN1Primitive);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "country_", "LNSString;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "typeOfSubstitution_", "LLibOrgBouncycastleAsn1X500DirectoryString;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "thirdPerson_", "LLibOrgBouncycastleAsn1X509GeneralName;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "certRef_", "LLibOrgBouncycastleAsn1X509IssuerSerial;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "getInstance", "LNSObject;", "LLibOrgBouncycastleAsn1ASN1Sequence;", "LNSString;LLibOrgBouncycastleAsn1X500DirectoryString;LLibOrgBouncycastleAsn1X509IssuerSerial;", "LNSString;LLibOrgBouncycastleAsn1X500DirectoryString;LLibOrgBouncycastleAsn1X509GeneralName;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleAsn1IsismttX509ProcurationSyntax = { "ProcurationSyntax", "lib.org.bouncycastle.asn1.isismtt.x509", ptrTable, methods, fields, 7, 0x1, 9, 4, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleAsn1IsismttX509ProcurationSyntax;
}

@end

LibOrgBouncycastleAsn1IsismttX509ProcurationSyntax *LibOrgBouncycastleAsn1IsismttX509ProcurationSyntax_getInstanceWithId_(id obj) {
  LibOrgBouncycastleAsn1IsismttX509ProcurationSyntax_initialize();
  if (obj == nil || [obj isKindOfClass:[LibOrgBouncycastleAsn1IsismttX509ProcurationSyntax class]]) {
    return (LibOrgBouncycastleAsn1IsismttX509ProcurationSyntax *) cast_chk(obj, [LibOrgBouncycastleAsn1IsismttX509ProcurationSyntax class]);
  }
  if ([obj isKindOfClass:[LibOrgBouncycastleAsn1ASN1Sequence class]]) {
    return new_LibOrgBouncycastleAsn1IsismttX509ProcurationSyntax_initWithLibOrgBouncycastleAsn1ASN1Sequence_((LibOrgBouncycastleAsn1ASN1Sequence *) obj);
  }
  @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$$", @"illegal object in getInstance: ", [[obj java_getClass] getName]));
}

void LibOrgBouncycastleAsn1IsismttX509ProcurationSyntax_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1IsismttX509ProcurationSyntax *self, LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  if ([((LibOrgBouncycastleAsn1ASN1Sequence *) nil_chk(seq)) size] < 1 || [seq size] > 3) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$I", @"Bad sequence size: ", [seq size]));
  }
  id<JavaUtilEnumeration> e = [seq getObjects];
  while ([((id<JavaUtilEnumeration>) nil_chk(e)) hasMoreElements]) {
    LibOrgBouncycastleAsn1ASN1TaggedObject *o = LibOrgBouncycastleAsn1ASN1TaggedObject_getInstanceWithId_([e nextElement]);
    {
      id<LibOrgBouncycastleAsn1ASN1Encodable> signingFor;
      switch ([((LibOrgBouncycastleAsn1ASN1TaggedObject *) nil_chk(o)) getTagNo]) {
        case 1:
        self->country_ = [((LibOrgBouncycastleAsn1DERPrintableString *) nil_chk(LibOrgBouncycastleAsn1DERPrintableString_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(o, true))) getString];
        break;
        case 2:
        self->typeOfSubstitution_ = LibOrgBouncycastleAsn1X500DirectoryString_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(o, true);
        break;
        case 3:
        signingFor = [o getObject];
        if ([signingFor isKindOfClass:[LibOrgBouncycastleAsn1ASN1TaggedObject class]]) {
          self->thirdPerson_ = LibOrgBouncycastleAsn1X509GeneralName_getInstanceWithId_(signingFor);
        }
        else {
          self->certRef_ = LibOrgBouncycastleAsn1X509IssuerSerial_getInstanceWithId_(signingFor);
        }
        break;
        default:
        @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$I", @"Bad tag number: ", [o getTagNo]));
      }
    }
  }
}

LibOrgBouncycastleAsn1IsismttX509ProcurationSyntax *new_LibOrgBouncycastleAsn1IsismttX509ProcurationSyntax_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1IsismttX509ProcurationSyntax, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

LibOrgBouncycastleAsn1IsismttX509ProcurationSyntax *create_LibOrgBouncycastleAsn1IsismttX509ProcurationSyntax_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1IsismttX509ProcurationSyntax, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

void LibOrgBouncycastleAsn1IsismttX509ProcurationSyntax_initWithNSString_withLibOrgBouncycastleAsn1X500DirectoryString_withLibOrgBouncycastleAsn1X509IssuerSerial_(LibOrgBouncycastleAsn1IsismttX509ProcurationSyntax *self, NSString *country, LibOrgBouncycastleAsn1X500DirectoryString *typeOfSubstitution, LibOrgBouncycastleAsn1X509IssuerSerial *certRef) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->country_ = country;
  self->typeOfSubstitution_ = typeOfSubstitution;
  self->thirdPerson_ = nil;
  self->certRef_ = certRef;
}

LibOrgBouncycastleAsn1IsismttX509ProcurationSyntax *new_LibOrgBouncycastleAsn1IsismttX509ProcurationSyntax_initWithNSString_withLibOrgBouncycastleAsn1X500DirectoryString_withLibOrgBouncycastleAsn1X509IssuerSerial_(NSString *country, LibOrgBouncycastleAsn1X500DirectoryString *typeOfSubstitution, LibOrgBouncycastleAsn1X509IssuerSerial *certRef) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1IsismttX509ProcurationSyntax, initWithNSString_withLibOrgBouncycastleAsn1X500DirectoryString_withLibOrgBouncycastleAsn1X509IssuerSerial_, country, typeOfSubstitution, certRef)
}

LibOrgBouncycastleAsn1IsismttX509ProcurationSyntax *create_LibOrgBouncycastleAsn1IsismttX509ProcurationSyntax_initWithNSString_withLibOrgBouncycastleAsn1X500DirectoryString_withLibOrgBouncycastleAsn1X509IssuerSerial_(NSString *country, LibOrgBouncycastleAsn1X500DirectoryString *typeOfSubstitution, LibOrgBouncycastleAsn1X509IssuerSerial *certRef) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1IsismttX509ProcurationSyntax, initWithNSString_withLibOrgBouncycastleAsn1X500DirectoryString_withLibOrgBouncycastleAsn1X509IssuerSerial_, country, typeOfSubstitution, certRef)
}

void LibOrgBouncycastleAsn1IsismttX509ProcurationSyntax_initWithNSString_withLibOrgBouncycastleAsn1X500DirectoryString_withLibOrgBouncycastleAsn1X509GeneralName_(LibOrgBouncycastleAsn1IsismttX509ProcurationSyntax *self, NSString *country, LibOrgBouncycastleAsn1X500DirectoryString *typeOfSubstitution, LibOrgBouncycastleAsn1X509GeneralName *thirdPerson) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->country_ = country;
  self->typeOfSubstitution_ = typeOfSubstitution;
  self->thirdPerson_ = thirdPerson;
  self->certRef_ = nil;
}

LibOrgBouncycastleAsn1IsismttX509ProcurationSyntax *new_LibOrgBouncycastleAsn1IsismttX509ProcurationSyntax_initWithNSString_withLibOrgBouncycastleAsn1X500DirectoryString_withLibOrgBouncycastleAsn1X509GeneralName_(NSString *country, LibOrgBouncycastleAsn1X500DirectoryString *typeOfSubstitution, LibOrgBouncycastleAsn1X509GeneralName *thirdPerson) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1IsismttX509ProcurationSyntax, initWithNSString_withLibOrgBouncycastleAsn1X500DirectoryString_withLibOrgBouncycastleAsn1X509GeneralName_, country, typeOfSubstitution, thirdPerson)
}

LibOrgBouncycastleAsn1IsismttX509ProcurationSyntax *create_LibOrgBouncycastleAsn1IsismttX509ProcurationSyntax_initWithNSString_withLibOrgBouncycastleAsn1X500DirectoryString_withLibOrgBouncycastleAsn1X509GeneralName_(NSString *country, LibOrgBouncycastleAsn1X500DirectoryString *typeOfSubstitution, LibOrgBouncycastleAsn1X509GeneralName *thirdPerson) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1IsismttX509ProcurationSyntax, initWithNSString_withLibOrgBouncycastleAsn1X500DirectoryString_withLibOrgBouncycastleAsn1X509GeneralName_, country, typeOfSubstitution, thirdPerson)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleAsn1IsismttX509ProcurationSyntax)
