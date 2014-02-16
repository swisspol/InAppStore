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

#import <Foundation/Foundation.h>

@class InAppStore;

@protocol InAppStoreDelegate <NSObject>
@optional
- (void)inAppStoreWillStartPurchasing:(InAppStore*)store;
- (void)inAppStoreDidCancelPurchase:(InAppStore*)store;
- (void)inAppStore:(InAppStore*)store didFindProductWithIdentifier:(NSString*)identifier price:(NSDecimalNumber*)price currencyLocale:(NSLocale*)locale;
- (void)inAppStore:(InAppStore*)store didFailFindingProductWithIdentifier:(NSString*)identifier;
- (void)inAppStore:(InAppStore*)store didFailPurchasingProductWithIdentifier:(NSString*)identifier error:(NSError*)error;
- (void)inAppStore:(InAppStore*)store didPurchaseProductWithIdentifier:(NSString*)identifier;  // Can be called while not purchasing if finishing an interrupted purchase
- (void)inAppStoreDidEndPurchasing:(InAppStore*)store;

- (void)inAppStoreWillStartRestoring:(InAppStore*)store;
- (void)inAppStoreDidCancelRestore:(InAppStore*)store;
- (void)inAppStore:(InAppStore*)store didFailRestoreWithError:(NSError*)error;
- (void)inAppStore:(InAppStore*)store didRestoreProductWithIdentifier:(NSString*)identifier;  // Can be called while not restoring if finishing an interrupted restore
- (void)inAppStoreDidEndRestoring:(InAppStore*)store;
@end

@interface InAppStore : NSObject
@property(nonatomic, assign) id<InAppStoreDelegate> delegate;
@property(nonatomic, getter = isPurchasing) BOOL purchasing;
@property(nonatomic, getter = isRestoring) BOOL restoring;
+ (InAppStore*)sharedStore;
- (BOOL)hasPurchasedProductWithIdentifier:(NSString*)identifier;
- (BOOL)purchaseProductWithIdentifier:(NSString*)identifier;  // Returns NO if no internet connection or purchases not allowed
- (BOOL)restorePurchases;  // Returns NO if no internet connection
@end
