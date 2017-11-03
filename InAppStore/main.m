/*
 Copyright (c) 2014, Pierre-Olivier Latour
 All rights reserved.
 
 Redistribution and use in source and binary forms, with or without
 modification, are permitted provided that the following conditions are met:
 * Redistributions of source code must retain the above copyright
 notice, this list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright
 notice, this list of conditions and the following disclaimer in the
 documentation and/or other materials provided with the distribution.
 * The name of Pierre-Olivier Latour may not be used to endorse
 or promote products derived from this software without specific
 prior written permission.
 
 THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 DISCLAIMED. IN NO EVENT SHALL PIERRE-OLIVIER LATOUR BE LIABLE FOR ANY
 DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 IMPORTANT: This file requires preprocessor definitions for "__BUNDLE_ID__" and "__BUNDLE_VERSION__"
 */

#import <Cocoa/Cocoa.h>
#import <CommonCrypto/CommonDigest.h>
#import <Security/CMSDecoder.h>
#import <Security/SecAsn1Coder.h>
#import <Security/SecAsn1Templates.h>
#import <Security/SecRequirement.h>
#import <IOKit/network/IOEthernetController.h>

#define ABORT(__MESSAGE__) \
  do { \
    fprintf(stderr, __MESSAGE__ "\n"); \
    exit(173); \
  } while(0)

// See https://developer.apple.com/library/mac/releasenotes/General/ValidateAppStoreReceipt/Chapters/ReceiptFields.html
enum {
  kReceiptAttributeType_BundleIdentifier = 2,  // UTF8STRING
  kReceiptAttributeType_AppVersion = 3,  // UTF8STRING
  kReceiptAttributeType_OpaqueValue = 4,  // Series of bytes
  kReceiptAttributeType_SHA1Hash = 5,  // 20 bytes SHA-1 digest
  kReceiptAttributeType_OriginalApplicationVersion = 19,  // UTF8STRING
  kReceiptAttributeType_ReceiptExpirationDate = 21,  // IA5STRING as RFC 3339 date
  
  kReceiptAttributeType_InAppPurchaseReceipt = 17,  // SET
  kReceiptAttributeType_InApp_Quantity = 1701,  // INTEGER
  kReceiptAttributeType_InApp_ProductIdentifier = 1702,  // UTF8STRING
  kReceiptAttributeType_InApp_TransactionIdentifier = 1703,  // UTF8STRING
  kReceiptAttributeType_InApp_PurchaseDate = 1704,  // IA5STRING as RFC 3339 date
  kReceiptAttributeType_InApp_OriginalTransactionIdentifier = 1705,  // UTF8STRING
  kReceiptAttributeType_InApp_OriginalPurchaseDate = 1706,  // IA5STRING as RFC 3339 date
  kReceiptAttributeType_InApp_SubscriptionExpirationDate = 1708,  // IA5STRING as RFC 3339 date
  kReceiptAttributeType_InApp_WebOrderLineItemID = 1711,  // INTEGER
  kReceiptAttributeType_InApp_CancellationDate = 1712  // IA5STRING as RFC 3339 date
};

typedef struct {
  size_t length;
  unsigned char *data;
} ASN1_Data;

typedef struct {
  ASN1_Data type;     // INTEGER
  ASN1_Data version;  // INTEGER
  ASN1_Data value;    // OCTET STRING
} ReceiptAttribute;

typedef struct {
  ReceiptAttribute** attrs;
} ReceiptPayload;

typedef int (*ApplicationMain)(int argc, const char* argv[]);

extern CFMutableSetRef InAppPurchaseProductIdentifiers;

CFMutableSetRef InAppPurchaseProductIdentifiers = NULL;

static ApplicationMain _appMain = &NSApplicationMain;

// ASN.1 receipt attribute template
static const SecAsn1Template kReceiptAttributeTemplate[] = {
  { SEC_ASN1_SEQUENCE, 0, NULL, sizeof(ReceiptAttribute) },
  { SEC_ASN1_INTEGER, offsetof(ReceiptAttribute, type), NULL, 0 },
  { SEC_ASN1_INTEGER, offsetof(ReceiptAttribute, version), NULL, 0 },
  { SEC_ASN1_OCTET_STRING, offsetof(ReceiptAttribute, value), NULL, 0 },
  { 0, 0, NULL, 0 }
};

// ASN.1 receipt template set
static const SecAsn1Template kSetOfReceiptAttributeTemplate[] = {
  { SEC_ASN1_SET_OF, 0, kReceiptAttributeTemplate, sizeof(ReceiptPayload) },
  { 0, 0, NULL, 0 }
};

inline static void _CheckBundleIDAndVersion() {
  CFDictionaryRef info = CFBundleGetInfoDictionary(CFBundleGetMainBundle());
  CFStringRef bundleID = CFDictionaryGetValue(info, CFSTR("CFBundleIdentifier"));
  if (!CFEqual(bundleID, CFSTR(__BUNDLE_ID__))) {
    ABORT("Failed checking bundle ID");
  }
  CFStringRef bundleVersion = CFDictionaryGetValue(info, CFSTR("CFBundleShortVersionString"));
  if (!CFEqual(bundleVersion, CFSTR(__BUNDLE_VERSION__))) {
    ABORT("Failed checking bundle version");
  }
}

inline static void _CheckBundleSignature() {
  CFURLRef url = CFBundleCopyBundleURL(CFBundleGetMainBundle());
  SecStaticCodeRef staticCode = NULL;
  if (SecStaticCodeCreateWithPath(url, kSecCSDefaultFlags, &staticCode) != errSecSuccess) {
    ABORT("Failed checking bundle signature: create static code");
  }
  SecRequirementRef requirement = NULL;
  if (SecRequirementCreateWithString(CFSTR("anchor apple generic"), kSecCSDefaultFlags, &requirement) != errSecSuccess) {
    ABORT("Failed checking bundle signature: create requirement");
  }
  if (SecStaticCodeCheckValidity(staticCode, kSecCSDefaultFlags, requirement) != errSecSuccess) {
    ABORT("Failed checking bundle signature: check static code validity");
  }
  CFRelease(staticCode);
  CFRelease(requirement);
  CFRelease(url);
}

inline static CFDataRef _CopyDecryptedReceiptData() {
  CFURLRef baseURL = CFBundleCopyBundleURL(CFBundleGetMainBundle());
  CFURLRef relativeURL = CFURLCreateWithString(kCFAllocatorDefault, CFSTR("Contents/_MASReceipt/receipt"), baseURL);
  CFURLRef receiptURL = CFURLCopyAbsoluteURL(relativeURL);
  CFStringRef receiptPath = CFURLCopyFileSystemPath(receiptURL, kCFURLPOSIXPathStyle);
  char buffer[PATH_MAX];
  if (!CFStringGetCString(receiptPath, buffer, sizeof(buffer), kCFStringEncodingUTF8)) {
    ABORT("Failed decrypting receipt: get receipt path");
  }
  int file = open(buffer, O_RDONLY);
  if (file <= 0) {
    ABORT("Failed decrypting receipt: open file");
  }
  lseek(file, 0, SEEK_END);
  ssize_t receiptSize = lseek(file, 0, SEEK_CUR);
  lseek(file, 0, SEEK_SET);
  void* receiptBytes = malloc(receiptSize);
  if ((receiptSize <= 0) || (read(file, receiptBytes, receiptSize) != receiptSize)) {
    ABORT("Failed decrypting receipt: read file");
  }
  
  CMSDecoderRef decoder = NULL;
  if (CMSDecoderCreate(&decoder) != noErr) {
    ABORT("Failed decrypting receipt: create decoder");
  }
  if (CMSDecoderUpdateMessage(decoder, receiptBytes, receiptSize) != noErr) {
    ABORT("Failed decrypting receipt: update decoder message");
  }
  if (CMSDecoderFinalizeMessage(decoder) != noErr) {
    ABORT("Failed decrypting receipt: finalize decoder message");
  }
  CFDataRef data = NULL;
  if (CMSDecoderCopyContent(decoder, &data) != noErr) {
    ABORT("Failed decrypting receipt: get decoder content");
  }
  size_t numSigners = 0;
  if ((CMSDecoderGetNumSigners(decoder, &numSigners) != noErr) || (numSigners == 0)) {
    ABORT("Failed decrypting receipt: get signer count");
  }
  SecPolicyRef policy = SecPolicyCreateBasicX509();
  SecTrustRef signerTrust = NULL;
  CMSSignerStatus signerStatus = 0;
  OSStatus certVerifyResult = 0;
  if ((CMSDecoderCopySignerStatus(decoder, 0, policy, true, &signerStatus, &signerTrust, &certVerifyResult) != noErr) || (signerStatus != kCMSSignerValid)) {
    ABORT("Failed decrypting receipt: get signer status");
  }
  CFRelease(signerTrust);
  CFRelease(policy);
  CFRelease(decoder);
  
  free(receiptBytes);
  close(file);
  CFRelease(receiptPath);
  CFRelease(receiptURL);
  CFRelease(relativeURL);
  CFRelease(baseURL);
  return data;
}

inline static CFDataRef _CopyMACAddress() {
  CFDataRef data = NULL;
  mach_port_t masterPort;
  if (IOMasterPort(MACH_PORT_NULL, &masterPort) == KERN_SUCCESS) {
    CFMutableDictionaryRef matchingDict = IOBSDNameMatching(masterPort, 0, "en0");
    io_iterator_t iterator;
    if (IOServiceGetMatchingServices(masterPort, matchingDict, &iterator) == KERN_SUCCESS) {  // Consumes a reference to "matchingDict"
      io_object_t service;
      while ((service = IOIteratorNext(iterator)) != 0) {
        io_object_t parentService;
        if (IORegistryEntryGetParentEntry(service, kIOServicePlane, &parentService) == KERN_SUCCESS) {
          if (data == NULL) {
            data = (CFDataRef)IORegistryEntryCreateCFProperty(parentService, CFSTR(kIOMACAddress), kCFAllocatorDefault, 0);
          }
          IOObjectRelease(parentService);
        }
        IOObjectRelease(service);
      }
      IOObjectRelease(iterator);
    }
  }
  if (data == NULL) {
    ABORT("Failed retrieving primary MAC address");
  }
  return data;
}

inline static CFDataRef _CopyRawDataFromASN1Data(const ASN1_Data* asn1Data) {
  return CFDataCreate(kCFAllocatorDefault, asn1Data->data, asn1Data->length);
}

inline static int _GetIntValueFromASN1Data(const ASN1_Data* asn1Data) {
  int ret = 0;
  for (int i = 0; i < (int)asn1Data->length; i++) {
    ret = (ret << 8) | asn1Data->data[i];
  }
  return ret;
}

// Can return NULL
inline static CFStringRef _CopyUTF8StringFromASN1Data(SecAsn1CoderRef decoder, const ASN1_Data* asn1Data) {
  ASN1_Data data;
  if (SecAsn1Decode(decoder, asn1Data->data, asn1Data->length, kSecAsn1UTF8StringTemplate, &data) != noErr) {
    ABORT("Failed decoding receipt field: decode UTF-8 string");
  }
  return CFStringCreateWithBytes(kCFAllocatorDefault, data.data, data.length, kCFStringEncodingUTF8, false);
}

// Can return NULL
inline static CFDateRef _CopyDateFromASN1Data(SecAsn1CoderRef decoder, const ASN1_Data* asn1Data) {
  ASN1_Data data;
  if (SecAsn1Decode(decoder, asn1Data->data, asn1Data->length, kSecAsn1IA5StringTemplate, &data) != noErr) {
    ABORT("Failed decoding receipt field: decode date");
  }
  CFStringRef string = CFStringCreateWithBytes(kCFAllocatorDefault, data.data, data.length, kCFStringEncodingASCII, false);
  CFLocaleRef locale = CFLocaleCreate(kCFAllocatorDefault, CFSTR("en_US"));
  CFDateFormatterRef formatter = CFDateFormatterCreate(kCFAllocatorDefault, locale, kCFDateFormatterNoStyle, kCFDateFormatterNoStyle);
  CFDateFormatterSetFormat(formatter, CFSTR("yyyy'-'MM'-'dd'T'HH':'mm':'ss'Z'"));
  CFDateRef date = CFDateFormatterCreateDateFromString(kCFAllocatorDefault, formatter, string, NULL);
  CFRelease(formatter);
  CFRelease(locale);
  CFRelease(string);
  return date;
}

inline static void _CheckInAppPurchasePayload(CFDataRef receiptData) {
  SecAsn1CoderRef asn1Decoder = NULL;
  if (SecAsn1CoderCreate(&asn1Decoder) != noErr) {
    ABORT("Failed validating IAP receipt: create decoder");
  }
  ReceiptPayload payload = {0};
  if (SecAsn1Decode(asn1Decoder, CFDataGetBytePtr(receiptData), CFDataGetLength(receiptData), kSetOfReceiptAttributeTemplate, &payload) != noErr) {
    ABORT("Failed validating IAP receipt: decode payload");
  }
  
  CFStringRef productID = NULL;
  CFDateRef purchaseDate = NULL;
  int quantity = 0;
  CFDateRef cancellationDate = NULL;
  ReceiptAttribute* attribute;
  for (int i = 0; (attribute = payload.attrs[i]); ++i) {
    int type = _GetIntValueFromASN1Data(&attribute->type);
    switch (type) {
      
      case kReceiptAttributeType_InApp_ProductIdentifier:
        productID = _CopyUTF8StringFromASN1Data(asn1Decoder, &attribute->value);
        break;
      
      case kReceiptAttributeType_InApp_Quantity:
        quantity = _GetIntValueFromASN1Data(&attribute->value);
        break;
      
      case kReceiptAttributeType_InApp_PurchaseDate:
        purchaseDate = _CopyDateFromASN1Data(asn1Decoder, &attribute->value);
        break;
      
      case kReceiptAttributeType_InApp_CancellationDate:
        cancellationDate = _CopyDateFromASN1Data(asn1Decoder, &attribute->value);
        break;
      
    }
  }
  if ((productID == NULL) || (purchaseDate == NULL) || (quantity <= 0)) {
    ABORT("Failed validating IAP receipt: check product");
  }
  if (!cancellationDate) {
    CFSetAddValue(InAppPurchaseProductIdentifiers, productID);
#if DEBUG
    char buffer[512];
    CFStringGetCString(productID, buffer, sizeof(buffer), kCFStringEncodingUTF8);
    fprintf(stdout, "Found in-app purchase receipt for product '%s'\n", buffer);
#endif
  }
  CFRelease(purchaseDate);
  CFRelease(productID);
  
  SecAsn1CoderRelease(asn1Decoder);
}

inline static void _CheckReceiptPayload() {
  CFDataRef receiptData = _CopyDecryptedReceiptData();
  SecAsn1CoderRef asn1Decoder = NULL;
  if (SecAsn1CoderCreate(&asn1Decoder) != noErr) {
    ABORT("Failed validating app receipt: create decoder");
  }
  ReceiptPayload payload = {0};
  if (SecAsn1Decode(asn1Decoder, CFDataGetBytePtr(receiptData), CFDataGetLength(receiptData), kSetOfReceiptAttributeTemplate, &payload) != noErr) {
    ABORT("Failed validating app receipt: decode payload");
  }
  
  CFStringRef bundleID = NULL;
  CFDataRef bundleData = NULL;
  CFStringRef bundleVersion = NULL;
  CFDataRef opaqueValue = NULL;
  CFDataRef sha1Hash = NULL;
  ReceiptAttribute* attribute;
  for (int i = 0; (attribute = payload.attrs[i]); ++i) {
    int type = _GetIntValueFromASN1Data(&attribute->type);
    switch (type) {
      
      case kReceiptAttributeType_BundleIdentifier:
        bundleID = _CopyUTF8StringFromASN1Data(asn1Decoder, &attribute->value);
        bundleData = _CopyRawDataFromASN1Data(&attribute->value);
        break;
      
      case kReceiptAttributeType_AppVersion:
        bundleVersion = _CopyUTF8StringFromASN1Data(asn1Decoder, &attribute->value);
        break;
      
      case kReceiptAttributeType_OpaqueValue:
        opaqueValue = _CopyRawDataFromASN1Data(&attribute->value);
        break;
      
      case kReceiptAttributeType_SHA1Hash:
        sha1Hash = _CopyRawDataFromASN1Data(&attribute->value);
        break;
      
      case kReceiptAttributeType_InAppPurchaseReceipt: {
        CFDataRef iapData = _CopyRawDataFromASN1Data(&attribute->value);
        _CheckInAppPurchasePayload(iapData);
        CFRelease(iapData);
        break;
      }
      
    }
  }
  if (!bundleID || !CFEqual(bundleID, CFSTR(__BUNDLE_ID__))) {
    ABORT("Failed validating app receipt: check bundle ID");
  }
#if !DEBUG
  if (!bundleVersion || !CFEqual(bundleVersion, CFSTR(__BUNDLE_VERSION__))) {
    ABORT("Failed validating app receipt: check bundle version");
  }
#endif
  if (bundleData && opaqueValue && sha1Hash && (CFDataGetLength(sha1Hash) == CC_SHA1_DIGEST_LENGTH)) {
    CFDataRef macAddress = _CopyMACAddress();
    CFMutableDataRef digestData = CFDataCreateMutable(kCFAllocatorDefault, 0);
    CFDataAppendBytes(digestData, CFDataGetBytePtr(macAddress), CFDataGetLength(macAddress));
    CFDataAppendBytes(digestData, CFDataGetBytePtr(opaqueValue), CFDataGetLength(opaqueValue));
    CFDataAppendBytes(digestData, CFDataGetBytePtr(bundleData), CFDataGetLength(bundleData));
    unsigned char digestBuffer[CC_SHA1_DIGEST_LENGTH];
    CC_SHA1(CFDataGetBytePtr(digestData), (CC_LONG)CFDataGetLength(digestData), digestBuffer);
    if (memcmp(digestBuffer, CFDataGetBytePtr(sha1Hash), CC_SHA1_DIGEST_LENGTH)) {
      ABORT("Failed validating app receipt: check hash");
    }
    CFRelease(digestData);
    CFRelease(macAddress);
  } else {
    ABORT("Failed validating app receipt: check hash");
  }
  CFRelease(sha1Hash);
  CFRelease(opaqueValue);
  CFRelease(bundleData);
  CFRelease(bundleVersion);
  CFRelease(bundleID);
  
  SecAsn1CoderRelease(asn1Decoder);
  CFRelease(receiptData);
}

int main(int argc, char *argv[]) {
  InAppPurchaseProductIdentifiers = CFSetCreateMutable(kCFAllocatorDefault, 0, &kCFCopyStringSetCallBacks);
  _CheckBundleIDAndVersion();
  _CheckBundleSignature();
#if !DEBUG
  _CheckReceiptPayload();
#else
  fprintf(stderr, "<<< WARNING: APP STORE RECEIPT VALIDATION RUNNING IN DEBUG MODE >>>\n");
  @autoreleasepool {
    if ([[NSFileManager defaultManager] fileExistsAtPath:[[[NSBundle mainBundle] appStoreReceiptURL] path]]) {
      _CheckReceiptPayload();
    }
  }
#endif
  return _appMain(argc, (const char**)argv);
}
