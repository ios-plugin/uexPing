/**
 *
 *	@file   	: EUExPing.m  in EUExPing
 *
 *	@author 	: CeriNo
 * 
 *	@date   	: 16/8/12
 *
 *	@copyright 	: 2016 The AppCan Open Source Project.
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Lesser General Public License for more details.
 *  You should have received a copy of the GNU Lesser General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */


#import "EUExPing.h"
#import <ReactiveCocoa/ReactiveCocoa.h>
#import "uexPingClient.h"
#import "JSON.h"
#import "EUtility.h"


@interface UexTest : NSObject

@end
@implementation UexTest

- (void)test{
    uexPingClient *client = [[uexPingClient alloc]initWithHostName:@"www.baidu.com"];
    client.pingTimes = 10;
    RACDisposable *disposable = [[client launchSignal]subscribeNext:^(uexPingResult *result){
        NSLog(@"%@",result);
    }error:^(NSError *error) {
        NSLog(@" ping error:%@",error.localizedDescription);
    }completed:^{
        NSLog(@"ping complete!");
    }];
    [self.rac_deallocDisposable addDisposable:disposable];
    @weakify(client)
    [[RACScheduler scheduler]afterDelay:5 schedule:^{
        @strongify(client);
    }];
}

- (void)dealloc{
    NSLog(@"TEST dealloc!");
}
@end

@interface EUExPing ()
@property (nonatomic,strong)uexPingClient *client;
@property (nonatomic,strong)RACCommand *command;
@end
@implementation EUExPing




- (void)test:(NSMutableArray *)inArguments{
    
    uexPingClient *client = [[uexPingClient alloc]initWithHostName:@"www.baidu.com"];
    client.pingTimes = 10;
    RACDisposable *disposable = [[client launchSignal]subscribeNext:^(uexPingResult *result){
        NSLog(@"%@",result);
    }error:^(NSError *error) {
        NSLog(@" ping error:%@",error.localizedDescription);
    }completed:^{
        NSLog(@"ping complete!");
    }];
    [[client launchSignal]subscribeNext:^(uexPingResult *result){
        NSLog(@"%@",result);
    }error:^(NSError *error) {
        NSLog(@" ping error:%@",error.localizedDescription);
    }completed:^{
        NSLog(@"ping complete!");
    }];
    [self.rac_deallocDisposable addDisposable:disposable];
}

- (void)start:(NSMutableArray *)inArguments{
    if([inArguments count] < 1){
        return;
    }
    id info = [inArguments[0] JSONValue];
    if(!info || ![info isKindOfClass:[NSArray class]]){
        return;
    }
    
    [info enumerateObjectsUsingBlock:^(NSString * _Nonnull host, NSUInteger idx, BOOL * _Nonnull stop) {
        if (![host isKindOfClass:[NSString class]]) {
            return;
        }
        RACDisposable *disposable = [self pingHost:host];
        [self.rac_deallocDisposable addDisposable:disposable];
    }];
    
}

- (RACDisposable *)pingHost:(NSString *)host{
    uexPingClient *client = [[uexPingClient alloc]initWithHostName:host];
    NSLog(@"%@",client);
    @weakify(self);
    return [[[client
                launchSignal]
                collect]
                subscribeNext:^(NSArray<uexPingResult *> *results) {
                    NSLog(@"%@",results);
                    @strongify(self);
                    NSMutableDictionary *basicData = [self basicJSONDataWithHost:host];
                    NSArray<NSNumber *> *validTimes = [[[[results.rac_sequence
                                                            filter:^BOOL(uexPingResult *result) {
                                                                return result.state == uexPingStateSuccess;
                                                            }]
                                                            map:^id(uexPingResult *result) {
                                                                return @(result.elapsedTime * 1000);
                                                            }]
                                                            array]
                                                            sortedArrayUsingComparator:^NSComparisonResult(NSNumber *  _Nonnull obj1, NSNumber *  _Nonnull obj2) {
                                                                return [obj1 compare:obj2];
                                                            }];
                    if (validTimes.count > 0){
                        [basicData setValue:validTimes.firstObject forKey:@"min"];
                        [basicData setValue:validTimes.lastObject forKey:@"max"];
                        double avg = [[validTimes.rac_sequence
                                       foldLeftWithStart:@0 reduce:^id(NSNumber *sum, NSNumber *time) {
                                           return @(sum.doubleValue + time.doubleValue);
                                       }] doubleValue] / validTimes.count;
                        [basicData setValue:@(avg) forKey:@"avg"];
                        [basicData setValue:@0 forKey:@"status"];
                    }
                    NSString *jsStr = [NSString stringWithFormat:@"if(uexPing.onStart){uexPing.onStart(0,1,%@);}",basicData.JSONFragment.JSONFragment];
                    [EUtility brwView:self.meBrwView evaluateScript:jsStr];
                }
                error:^(NSError *error) {
                    NSLog(@"errorr: %@",error.localizedDescription);
                    @strongify(self);
                    NSMutableDictionary *basicData = [self basicJSONDataWithHost:host];
                    NSString *jsStr = [NSString stringWithFormat:@"if(uexPing.onStart){uexPing.onStart(0,1,%@);}",basicData.JSONFragment.JSONFragment];
                    [EUtility brwView:self.meBrwView evaluateScript:jsStr];
                }];
    
}

- (NSMutableDictionary *)basicJSONDataWithHost:(NSString *)host{
    return [@{
      @"addr"     : host,
      @"status"   : @-1,
      @"avg"      : @0,
      @"min"      : @0,
      @"max"      : @0
      } mutableCopy];
    
}

@end