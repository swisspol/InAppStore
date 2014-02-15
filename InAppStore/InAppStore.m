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

#import <SystemConfiguration/SCNetworkReachability.h>
#import <StoreKit/StoreKit.h>

#import "InAppStore.h"

#define kReachabilityHostName "www.apple.com"

#ifdef NDEBUG
#define LOG(...)
#else
#define LOG(...) NSLog(__VA_ARGS__)
#endif

@interface InAppStore () <SKPaymentTransactionObserver, SKProductsRequestDelegate> {
  NSString* _productIdentifier;
}
@end

extern CFMutableSetRef InAppPurchaseProductIdentifiers;  // From main.m

static BOOL _CheckNetwork() {
  BOOL online = YES;
  SCNetworkReachabilityRef reachabilityRef = SCNetworkReachabilityCreateWithName(kCFAllocatorDefault, kReachabilityHostName);
  if (reachabilityRef) {
    SCNetworkConnectionFlags flags;
    if (SCNetworkReachabilityGetFlags(reachabilityRef, &flags) && (!(flags & kSCNetworkReachabilityFlagsReachable) || (flags & kSCNetworkReachabilityFlagsConnectionRequired))) {
      online = NO;
    }
    CFRelease(reachabilityRef);
  }
  return online;
}

@implementation InAppStore

+ (InAppStore*)sharedStore {
  static InAppStore* store = nil;
  static dispatch_once_t token = 0;
  dispatch_once(&token, ^{
    store = [[InAppStore alloc] init];
  });
  return store;
}

- (id)init {
  if ((self = [super init])) {
    [[SKPaymentQueue defaultQueue] addTransactionObserver:self];
  }
  return self;
}

- (BOOL)hasPurchasedProductWithIdentifier:(NSString*)identifier {
  return CFSetContainsValue(InAppPurchaseProductIdentifiers, (__bridge void*)identifier);
}

- (void)_start {
  if ([_delegate respondsToSelector:@selector(inAppStoreWillBecomeBusy:)]) {
    [_delegate inAppStoreWillBecomeBusy:self];
  }
  _busy = YES;
}

- (void)_end {
  _busy = NO;
  if ([_delegate respondsToSelector:@selector(inAppStoreDidBecomeIdle:)]) {
    [_delegate inAppStoreDidBecomeIdle:self];
  }
}

- (BOOL)purchaseProductWithIdentifier:(NSString*)identifier {
  if (_busy || !_CheckNetwork() || ![SKPaymentQueue canMakePayments]) {
    return NO;
  }
  LOG(@"[App Store] Product request started");
  _productIdentifier = identifier;
  SKProductsRequest* request = [[SKProductsRequest alloc] initWithProductIdentifiers:[NSSet setWithObject:identifier]];
  request.delegate = self;
  [request start];
  [self _start];
  return YES;
}

- (BOOL)restorePurchases {
  if (_busy || !_CheckNetwork()) {
    return NO;
  }
  LOG(@"[App Store] Restore started");
  [[SKPaymentQueue defaultQueue] restoreCompletedTransactions];
  [self _start];
  return YES;
}

- (void)productsRequest:(SKProductsRequest*)request didReceiveResponse:(SKProductsResponse*)response {
  SKProduct* product = [response.products firstObject];
  if (product) {
    LOG(@"[App Store] Product found: %@", product.productIdentifier);
    SKPayment* payment = [SKPayment paymentWithProduct:product];
    [[SKPaymentQueue defaultQueue] addPayment:payment];
  } else {
    NSString* productIdentifier = [response.invalidProductIdentifiers firstObject];
    LOG(@"[App Store] Invalid product: %@", productIdentifier);
    dispatch_async(dispatch_get_main_queue(), ^{
      if ([_delegate respondsToSelector:@selector(inAppStore:didFailFindingProductWithIdentifier:)]) {
        [_delegate inAppStore:self didFailFindingProductWithIdentifier:productIdentifier];
      }
      [self _end];
    });
  }
}

// Not called if -request:didFailWithError: is called
- (void)requestDidFinish:(SKRequest*)request {
  LOG(@"[App Store] Product request completed");
  _productIdentifier = nil;
}

- (void)request:(SKRequest*)request didFailWithError:(NSError*)error {
  LOG(@"[App Store] Product request failed (%li): %@", error.code, error.localizedDescription);
  NSString* productIdentifier = _productIdentifier;
  dispatch_async(dispatch_get_main_queue(), ^{
    if ([_delegate respondsToSelector:@selector(inAppStore:didFailPurchasingProductWithIdentifier:error:)]) {
      [_delegate inAppStore:self didFailPurchasingProductWithIdentifier:productIdentifier error:error];
    }
    [self _end];
  });
  _productIdentifier = nil;
}

// This can be called in response to a purchase or restore request but also on app cold launch if there are unfinished transactions still pending
- (void)paymentQueue:(SKPaymentQueue*)queue updatedTransactions:(NSArray*)transactions {
  for (SKPaymentTransaction* transaction in transactions) {
    NSString* productIdentifier = transaction.payment.productIdentifier;
    switch (transaction.transactionState) {
      
      case SKPaymentTransactionStatePurchasing:
        LOG(@"[App Store] Purchase started for product '%@'", transaction.payment.productIdentifier);
        break;
      
      case SKPaymentTransactionStatePurchased: {
        LOG(@"[App Store] Purchase completed for product '%@'", transaction.payment.productIdentifier);
        CFSetSetValue(InAppPurchaseProductIdentifiers, (__bridge void*)productIdentifier);
        if (_busy) {
          dispatch_async(dispatch_get_main_queue(), ^{
            if ([_delegate respondsToSelector:@selector(inAppStore:didPurchaseProductWithIdentifier:)]) {
              [_delegate inAppStore:self didPurchaseProductWithIdentifier:productIdentifier];
            }
            [self _end];
          });
        } else {
          // TODO: Handle stale transactions reconciled at launch
        }
        [[SKPaymentQueue defaultQueue] finishTransaction:transaction];
        break;
      }
      
      case SKPaymentTransactionStateRestored: {
        LOG(@"[App Store] Purchase restored for product '%@'", transaction.payment.productIdentifier);
        CFSetSetValue(InAppPurchaseProductIdentifiers, (__bridge void*)productIdentifier);
        if (_busy) {
          dispatch_async(dispatch_get_main_queue(), ^{
            if ([_delegate respondsToSelector:@selector(inAppStore:didRestoreProductWithIdentifier:)]) {
              [_delegate inAppStore:self didRestoreProductWithIdentifier:productIdentifier];
            }
          });
        } else {
          // TODO: Handle stale transactions reconciled at launch
        }
        [[SKPaymentQueue defaultQueue] finishTransaction:transaction];
        break;
      }
      
      case SKPaymentTransactionStateFailed: {
        NSError* error = transaction.error;
        LOG(@"[App Store] Purchased failed for product '%@' (%li): %@", transaction.payment.productIdentifier, error.code, error.localizedDescription);
        dispatch_async(dispatch_get_main_queue(), ^{
          if ([error.domain isEqualToString:SKErrorDomain] && ((error.code == 0) || (error.code == SKErrorPaymentCancelled))) {
            if ([_delegate respondsToSelector:@selector(inAppStoreDidCancelPurchase:)]) {
              [_delegate inAppStoreDidCancelPurchase:self];
            }
          } else {
            if ([_delegate respondsToSelector:@selector(inAppStore:didFailPurchasingProductWithIdentifier:error:)]) {
              [_delegate inAppStore:self didFailPurchasingProductWithIdentifier:productIdentifier error:error];
            }
          }
          [self _end];
        });
        [[SKPaymentQueue defaultQueue] finishTransaction:transaction];
        break;
      }
      
    }
  }
}

- (void)paymentQueue:(SKPaymentQueue*)queue restoreCompletedTransactionsFailedWithError:(NSError*)error {
  LOG(@"[App Store] Restore failed (%li): %@", error.code, error.localizedDescription);
  dispatch_async(dispatch_get_main_queue(), ^{
    if ([error.domain isEqualToString:SKErrorDomain] && (error.code == SKErrorPaymentCancelled)) {
      if ([_delegate respondsToSelector:@selector(inAppStoreDidCancelRestore:)]) {
        [_delegate inAppStoreDidCancelRestore:self];
      }
    } else {
      if ([_delegate respondsToSelector:@selector(inAppStore:didFailRestoreWithError:)]) {
        [_delegate inAppStore:self didFailRestoreWithError:error];
      }
    }
    [self _end];
  });
}

- (void)paymentQueueRestoreCompletedTransactionsFinished:(SKPaymentQueue*)queue {
  LOG(@"[App Store] Restore completed");
  dispatch_async(dispatch_get_main_queue(), ^{
    [self _end];
  });
}

@end
