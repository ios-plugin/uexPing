/**
 *
 *	@file   	: uexPingClient.h  in EUExPing
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


#import <Foundation/Foundation.h>
#import <ReactiveCocoa/ReactiveCocoa.h>


typedef NS_ENUM(NSInteger,uexPingState){
    uexPingStateSuccess,
    uexPingStateTimeout,
    uexPingStateFailure
};

@interface uexPingResult : NSObject

@property (nonatomic,strong)NSString *hostName;
@property (nonatomic,strong)NSString *hostAddress;
@property (nonatomic,assign)uint16_t sequenceNumber;
@property (nonatomic,assign)uexPingState state;
@property (nonatomic,strong)NSDate *requestTime;
@property (nonatomic,strong)NSDate *responseTime;
@property (nonatomic,assign,readonly)NSTimeInterval elapsedTime;
@property (nonatomic,strong)NSError *error;

@end




@interface uexPingClient: NSObject


@property (nonatomic,assign)NSTimeInterval pingInterval;//ping包最短间隔,默认1s
@property (nonatomic,assign)NSTimeInterval pingTimeout;//ping超时时长,默认1s
@property (nonatomic,assign)NSUInteger pingTimes;//默认5次
@property (nonatomic,strong,readonly)NSString *hostName;//由initWithHostName:接口传入的hostName

- (instancetype)init NS_UNAVAILABLE;
- (instancetype)initWithHostName:(NSString *)hostName NS_DESIGNATED_INITIALIZER;

/**
 *  开始进行数个ping操作
 *
 *  @return multicasted launchSignal
 *
 *  @discussion
        当前已经存在subscription时,sendError
        当发生错误时,sendError
        当client被dispose时,sendError
        正常情况下,会sendNext uexPingResult,表示每次ping操作的结果
        指定次数ping操作完成后,会立即sendCompleted
 *
 *  @discussion 
        如果launchSingal被subscribe,则client会被此subscription retain.
        在此期间,所有的ping操作会正常进行(除非client被dispose).
        直至subscription结束或者被dispose后,client才会被release.
 */
- (RACSignal *)launchSignal;


/**
 *  调用dispose之后,所有新的ping操作将不会进行,所有未完成或者新的launchSignal的subscription将会直接sendError
 *  dispose不会影响到已经开始但未结束的ping操作
 */
- (void)dispose;

@end

