/**
 *
 *	@file   	: uexPingClient.m  in EUExPing
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


#import "uexPingClient.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <AssertMacros.h>
#include <arpa/inet.h>


#pragma mark * ICMP On-The-Wire Format

/*! Describes the on-the-wire header format for an ICMP ping.
 *  \details This defines the header structure of ping packets on the wire.  Both IPv4 and
 *      IPv6 use the same basic structure.
 *
 *      This is declared in the header because clients of SimplePing might want to use
 *      it parse received ping packets.
 */

struct ICMPHeader {
    uint8_t     type;
    uint8_t     code;
    uint16_t    checksum;
    uint16_t    identifier;
    uint16_t    sequenceNumber;
    // data...
};
typedef struct ICMPHeader ICMPHeader;

__Check_Compile_Time(sizeof(ICMPHeader) == 8);
__Check_Compile_Time(offsetof(ICMPHeader, type) == 0);
__Check_Compile_Time(offsetof(ICMPHeader, code) == 1);
__Check_Compile_Time(offsetof(ICMPHeader, checksum) == 2);
__Check_Compile_Time(offsetof(ICMPHeader, identifier) == 4);
__Check_Compile_Time(offsetof(ICMPHeader, sequenceNumber) == 6);

enum {
    ICMPv4TypeEchoRequest = 8,          ///< The ICMP `type` for a ping request;
    ICMPv4TypeEchoReply   = 0           ///< The ICMP `type` for a ping response;
};

enum {
    ICMPv6TypeEchoRequest = 128,        ///< The ICMP `type` for a ping request;
    ICMPv6TypeEchoReply   = 129         ///< The ICMP `type` for a ping response;
};

#pragma mark * IPv4 and ICMPv4 On-The-Wire Format

struct IPv4Header {
    uint8_t     versionAndHeaderLength;
    uint8_t     differentiatedServices;
    uint16_t    totalLength;
    uint16_t    identification;
    uint16_t    flagsAndFragmentOffset;
    uint8_t     timeToLive;
    uint8_t     protocol;
    uint16_t    headerChecksum;
    uint8_t     sourceAddress[4];
    uint8_t     destinationAddress[4];
    // options...
    // data...
};
typedef struct IPv4Header IPv4Header;

__Check_Compile_Time(sizeof(IPv4Header) == 20);
__Check_Compile_Time(offsetof(IPv4Header, versionAndHeaderLength) == 0);
__Check_Compile_Time(offsetof(IPv4Header, differentiatedServices) == 1);
__Check_Compile_Time(offsetof(IPv4Header, totalLength) == 2);
__Check_Compile_Time(offsetof(IPv4Header, identification) == 4);
__Check_Compile_Time(offsetof(IPv4Header, flagsAndFragmentOffset) == 6);
__Check_Compile_Time(offsetof(IPv4Header, timeToLive) == 8);
__Check_Compile_Time(offsetof(IPv4Header, protocol) == 9);
__Check_Compile_Time(offsetof(IPv4Header, headerChecksum) == 10);
__Check_Compile_Time(offsetof(IPv4Header, sourceAddress) == 12);
__Check_Compile_Time(offsetof(IPv4Header, destinationAddress) == 16);

/*! Calculates an IP checksum.
 *  \details This is the standard BSD checksum code, modified to use modern types.
 *  \param buffer A pointer to the data to checksum.
 *  \param bufferLen The length of that data.
 *  \returns The checksum value, in network byte order.
 */

static uint16_t in_cksum(const void *buffer, size_t bufferLen) {
    //
    size_t              bytesLeft;
    int32_t             sum;
    const uint16_t *    cursor;
    union {
        uint16_t        us;
        uint8_t         uc[2];
    } last;
    uint16_t            answer;
    
    bytesLeft = bufferLen;
    sum = 0;
    cursor = buffer;
    
    /*
     * Our algorithm is simple, using a 32 bit accumulator (sum), we add
     * sequential 16 bit words to it, and at the end, fold back all the
     * carry bits from the top 16 bits into the lower 16 bits.
     */
    while (bytesLeft > 1) {
        sum += *cursor;
        cursor += 1;
        bytesLeft -= 2;
    }
    
    /* mop up an odd byte, if necessary */
    if (bytesLeft == 1) {
        last.uc[0] = * (const uint8_t *) cursor;
        last.uc[1] = 0;
        sum += last.us;
    }
    
    /* add back carry outs from top 16 bits to low 16 bits */
    sum = (sum >> 16) + (sum & 0xffff);	/* add hi 16 to low 16 */
    sum += (sum >> 16);			/* add carry */
    answer = (uint16_t) ~sum;   /* truncate to 16 bits */
    
    return answer;
}




#pragma mark - Ping Result


@interface uexPingResult ()
@property (nonatomic,strong)void (^completionBlock)(void);
@property (nonatomic,assign)BOOL isCompleted;
@end

@implementation uexPingResult


static NSMutableDictionary <NSNumber *,uexPingResult *> *availableResult;

- (instancetype)initWithSequenceNumber:(uint16_t)sequenceNumber
{
    self = [super init];
    if (self) {
        _requestTime = [NSDate date];
        _sequenceNumber = sequenceNumber;
    }
    return self;
}


- (void)timeout{
    if (self.isCompleted) {
        return;
    }
    self.state = uexPingStateTimeout;
    [self complete];
}

- (void)failWithError:(NSError *)error{
    if (self.isCompleted) {
        return;
    }
    self.state = uexPingStateFailure;
    self.error = error;
    [self complete];
}


- (void)succeed{
    if (self.isCompleted) {
        return;
    }
    self.responseTime = [NSDate date];
    self.state = uexPingStateSuccess;
    [self complete];
}
- (NSTimeInterval)elapsedTime{
    if (!self.responseTime) {
        return -1;
    }
    return [self.responseTime timeIntervalSinceDate:self.requestTime];
}

- (NSString *)description{
    NSMutableString *str = [@"" mutableCopy];
    [str appendFormat:@"uexPingResult<%p> - ping ",self];
    if ([self.hostName isEqual:self.hostAddress]) {
        [str appendString:self.hostName];
    }else{
        [str appendFormat:@"%@(%@)",self.hostName,self.hostAddress];
    }
    [str appendFormat:@" #%d ",self.sequenceNumber];
    switch (self.state) {
        case uexPingStateSuccess: {
            [str appendFormat:@"success, time: %f ms.",self.elapsedTime * 1000];
            break;
        }
        case uexPingStateTimeout: {
            [str appendFormat:@"timeout."];
            break;
        }
        case uexPingStateFailure: {
            [str appendFormat:@"error: %@.",self.error.localizedDescription];
            
            break;
        }
    }
    return [str copy];
}


- (void)complete{
    self.isCompleted = YES;
    
    void (^completionBlock)(void) = self.completionBlock;
    self.completionBlock = nil;
    if (completionBlock) {
        completionBlock();
    }
    
}



- (void)dealloc{
    //NSLog(@"result dealloc!");
}

@end


#pragma mark - Errors

typedef NS_ENUM(NSInteger,uexPingClientError){
    uexPingClientErrorAlreadyDisposedError = -1,
    uexPingClientErrorClientIsBusyError = -2,
    uexPingClientErrorHostResolutionError = -2,
    uexPingClientErrorSocketError = -4,
    uexPingClientErrorInvalidICMPPacketError = -5,
    
};


static NSString *const kUexPingErrorDomain = @"com.appcan.uexPing.errorDomain";
static inline NSError *clientHostResolutionError(){
    return [NSError errorWithDomain:kUexPingErrorDomain code:uexPingClientErrorHostResolutionError userInfo:@{NSLocalizedDescriptionKey:@"host resolution failed!"}];
}
static inline NSError *clientDisposedError(){
    return [NSError errorWithDomain:kUexPingErrorDomain code:uexPingClientErrorAlreadyDisposedError userInfo:@{NSLocalizedDescriptionKey:@"client has disposed!"}];
}
static inline NSError *clientSocketError(){
    return [NSError errorWithDomain:kUexPingErrorDomain code:uexPingClientErrorSocketError userInfo:@{NSLocalizedDescriptionKey:@"socket error!"}];
}
static inline NSError *clientICMPPacketError(){
    return [NSError errorWithDomain:kUexPingErrorDomain code:uexPingClientErrorInvalidICMPPacketError userInfo:@{NSLocalizedDescriptionKey:@"generate ICMP packet failed!"}];
}
static inline NSError *clientIsBusyError(){
    return [NSError errorWithDomain:kUexPingErrorDomain code:uexPingClientErrorClientIsBusyError userInfo:@{NSLocalizedDescriptionKey:@"client is busy!"}];
}
#pragma mark - Ping Client

@interface uexPingClient ()

@property (nonatomic,strong,readwrite)NSString *hostName;
@property (nonatomic,assign,readwrite)int64_t identifier;

//private
@property (nonatomic,strong)RACCommand *launchCommand;
@property (nonatomic,copy)NSData *hostAddress;
@property (nonatomic,strong)NSString *hostAddressString;
@property (nonatomic,strong)CFHostRef host __attribute__ ((NSObject));
@property (nonatomic,strong)CFSocketRef socket __attribute__ ((NSObject));
@property (nonatomic,assign,readonly)sa_family_t hostAddressFamily;
@property (nonatomic,strong)NSMutableDictionary<NSNumber *,uexPingResult *> *pingResults;
@property (nonatomic,strong)RACReplaySubject *disposeSignal;
@end

@implementation uexPingClient

#pragma mark - Public
- (instancetype)initWithHostName:(NSString *)hostName{
    self = [super init];
    if (self) {
        _hostName = [hostName copy];
        _identifier = (uint16_t) arc4random();
        _pingTimes = 5;
        _pingTimeout = 1;
        _pingInterval = 1;
        _pingResults = [NSMutableDictionary dictionary];
        _disposeSignal = [RACReplaySubject replaySubjectWithCapacity:1];
        @weakify(self);
        _launchCommand = [[RACCommand alloc]initWithEnabled:self.disposeSignal signalBlock:^RACSignal *(id input) {
            @strongify(self);
            return [[[[[self getHostInfoSignal]
                        subscribeOn:[RACScheduler scheduler]]
                        then:^RACSignal *{
                            return [self resolveHostAdressSignal];
                        }]
                        then:^RACSignal *{
                            return [self startSocketSignal];
                        }]
                        then:^RACSignal *{
                            return [self pingSignal];
                        }];
        }];
    }
    return self;
}


- (RACSignal *)launchSignal{
    if (self.launchCommand) {
        return [[self.launchCommand
                    execute:nil]
                    catch:^RACSignal *(NSError *error) {
                        if ([error.domain isEqual: RACCommandErrorDomain]) {
                            return [RACSignal error:clientIsBusyError()];
                        }else{
                            return [RACSignal error:error];
                        }
                    }];
    }
    return [RACSignal error:clientDisposedError()];
}

- (void)dispose{
    NSLog(@"client dispose!");
    [self.disposeSignal sendNext:@NO];
    [self clean];
}



#pragma mark - Cleaners

- (void)dealloc{
    [self clean];
    NSLog(@"client dealloc!");
}


- (void)clean{
    _launchCommand = nil;
    [self cleanHost];
    [self cleanSocket];
}

- (void)cleanHost{
    self.host = NULL;
    
}

- (void)cleanSocket{
    if (self.socket != NULL) {
        CFSocketInvalidate(self.socket);
        self.socket = NULL;
    }
}


#pragma mark - Getters



- (sa_family_t)hostAddressFamily{
    sa_family_t result = AF_UNSPEC;
    if (self.hostAddress && (self.hostAddress.length >= sizeof(struct sockaddr))) {
        result = ((const struct sockaddr *) self.hostAddress.bytes)->sa_family;
    }
    return result;
}



#pragma mark - ICMP Helper

/*! Calculates the offset of the ICMP header within an IPv4 packet.
 *  \details In the IPv4 case the kernel returns us a buffer that includes the
 *      IPv4 header.  We're not interested in that, so we have to skip over it.
 *      This code does a rough check of the IPv4 header and, if it looks OK,
 *      returns the offset of the ICMP header.
 *  \param packet The IPv4 packet, as returned to us by the kernel.
 *  \returns The offset of the ICMP header, or NSNotFound.
 */
static NSUInteger icmpHeaderOffsetInIPv4Packet(NSData *packet){
    // Returns the offset of the ICMPv4Header within an IP packet.
    NSUInteger                  result;
    const struct IPv4Header *   ipPtr;
    size_t                      ipHeaderLength;
    
    result = NSNotFound;
    if (packet.length >= (sizeof(IPv4Header) + sizeof(ICMPHeader))) {
        ipPtr = (const IPv4Header *) packet.bytes;
        if ( ((ipPtr->versionAndHeaderLength & 0xF0) == 0x40) &&            // IPv4
            ( ipPtr->protocol == IPPROTO_ICMP ) ) {
            ipHeaderLength = (ipPtr->versionAndHeaderLength & 0x0F) * sizeof(uint32_t);
            if (packet.length >= (ipHeaderLength + sizeof(ICMPHeader))) {
                result = ipHeaderLength;
            }
        }
    }
    return result;
}



- (NSData *)icmpPacketWithSequenceNumber:(uint16_t)sequenceNumber{
    NSData *payload = [[NSString stringWithFormat:@"%28zd bottles of beer on the wall", (ssize_t) 99 - (size_t) (sequenceNumber % 100) ] dataUsingEncoding:NSASCIIStringEncoding];
    ICMPHeader *icmpPtr;
    NSMutableData *packet = [NSMutableData dataWithLength:sizeof(*icmpPtr) + payload.length];
    icmpPtr = packet.mutableBytes;
    icmpPtr->checksum = 0;
    icmpPtr->code = 0;
    icmpPtr->identifier = OSSwapHostToBigInt16(self.identifier);
    icmpPtr->sequenceNumber = OSSwapHostToBigInt16(sequenceNumber);
    BOOL needCheckSum = NO;
    switch (self.hostAddressFamily) {
        case AF_INET:{
            icmpPtr->type = ICMPv4TypeEchoRequest;
            needCheckSum = YES;
            
            break;
        }
        case AF_INET6:{
            icmpPtr->type = ICMPv6TypeEchoRequest;
            break;
        }
        
        default:
            return nil;
    }

    memcpy(&icmpPtr[1], [payload bytes], [payload length]);
    if (needCheckSum) {
        icmpPtr->checksum = in_cksum(packet.bytes, packet.length);
    }
    return packet;
}





#pragma mark - CFNetWork Callback

static void SocketReadCallback(CFSocketRef s, CFSocketCallBackType type, CFDataRef address, const void *data, void *info) {
    uexPingClient *client = (__bridge uexPingClient *) info;
    assert([client isKindOfClass:[uexPingClient class]]);
    struct sockaddr_storage addr;
    socklen_t               addrLen;
    ssize_t                 bytesRead;
    static uint32_t kBufferSize = 65535;
    void * buffer = malloc(kBufferSize);
    @onExit{
        free(buffer);
    };
    addrLen = sizeof(addr);
    bytesRead = recvfrom(CFSocketGetNative(client.socket), buffer, kBufferSize, 0, (struct sockaddr *) &addr, &addrLen);
    if (bytesRead < 0) {
        return;
    }
    NSMutableData *packet = [NSMutableData dataWithBytes:buffer length:(NSUInteger) bytesRead];
    switch (client.hostAddressFamily) {
        case AF_INET: {
            [client readPing4ResponsePacket:packet];
        } break;
        case AF_INET6: {
            [client readPing6ResponsePacket:packet];
        } break;
        default:
            break;
    }

}

#pragma mark - Read Packet


- (void)readPing4ResponsePacket:(NSMutableData *)packet{
    
    NSUInteger icmpHeaderOffset = icmpHeaderOffsetInIPv4Packet(packet);
    if (icmpHeaderOffset == NSNotFound) {
        return;
    }
    ICMPHeader * icmpPtr = (struct ICMPHeader *) (((uint8_t *) packet.mutableBytes) + icmpHeaderOffset);
    uint16_t receivedChecksum   = icmpPtr->checksum;
    icmpPtr->checksum  = 0;
    uint16_t calculatedChecksum = in_cksum(icmpPtr, packet.length - icmpHeaderOffset);
    if (receivedChecksum != calculatedChecksum
        || icmpPtr->type != ICMPv4TypeEchoReply
        || OSSwapBigToHostInt16(icmpPtr->identifier) != self.identifier
        || icmpPtr->code != 0) {
        return;
    }
    uint16_t sequenceNumber = OSSwapBigToHostInt16(icmpPtr->sequenceNumber);
    [self.pingResults[@(sequenceNumber)] succeed];
}
- (void)readPing6ResponsePacket:(NSData *)packet{
    const ICMPHeader * icmpPtr;
    if (packet.length < sizeof(*icmpPtr)) {
        return;
    }

    icmpPtr = packet.bytes;
    if (icmpPtr->type != ICMPv6TypeEchoReply
        || OSSwapBigToHostInt16(icmpPtr->identifier) != self.identifier
        || icmpPtr->code != 0) {
        return;
    }
    uint16_t sequenceNumber = OSSwapBigToHostInt16(icmpPtr->sequenceNumber);
    [self.pingResults[@(sequenceNumber)] succeed];
    
}





#pragma mark - Private Signals
- (RACSignal *)getHostInfoSignal{
    return [[RACSignal createSignal:^RACDisposable *(id<RACSubscriber> subscriber) {
        self.host = (CFHostRef) CFAutorelease( CFHostCreateWithName(NULL, (__bridge CFStringRef) self.hostName) );
        CFStreamError streamError = {0,0};
        if (!CFHostStartInfoResolution(self.host, kCFHostAddresses, &streamError) || streamError.domain != 0) {
            [subscriber sendError:clientHostResolutionError()];
        }else{
            [subscriber sendCompleted];
        }
        return nil;
    }]doError:^(NSError *error) {
        [self cleanHost];
    }];
}
- (RACSignal *)resolveHostAdressSignal{
    @weakify(self);
    return [RACSignal createSignal:^RACDisposable *(id<RACSubscriber> subscriber) {
        @strongify(self);
        Boolean resolved;
        NSArray * addresses = (__bridge NSArray *) CFHostGetAddressing(self.host, &resolved);
        if (resolved && (addresses != nil) ) {
            resolved = false;
            for (NSData * address in addresses) {
                if (address.length < sizeof(struct sockaddr)) {
                    continue;
                }
                const struct sockaddr *addrPtr = (const struct sockaddr *) address.bytes;
                sa_family_t family = addrPtr->sa_family;
                if (family == AF_INET || family == AF_INET6) {
                    self.hostAddress = address;
                    struct sockaddr_in *sin = (struct sockaddr_in *)addrPtr;
                    char str[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &(sin->sin_addr), str, INET_ADDRSTRLEN);
                    self.hostAddressString = [[NSString alloc] initWithUTF8String:str];
                    resolved = true;
                    break;
                }
            }
        }
        if (resolved) {
            [subscriber sendCompleted];
        }else{
            [subscriber sendError:[NSError errorWithDomain:(NSString *)kCFErrorDomainCFNetwork code:kCFHostErrorHostNotFound userInfo:nil]];
        }
        return [RACDisposable disposableWithBlock:^{
            [self cleanHost];
        }];
    }];
}



- (RACSignal *)startSocketSignal{
    @weakify(self);
    return [[RACSignal createSignal:^RACDisposable *(id<RACSubscriber> subscriber) {
        @strongify(self);
        int err = 0;
        int fd = -1;
        assert(self.hostAddress != nil);
        switch (self.hostAddressFamily) {
            case AF_INET: {
                fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
                if (fd < 0) {
                    err = errno;
                }
            } break;
            case AF_INET6: {
                fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_ICMPV6);
                if (fd < 0) {
                    err = errno;
                }
            } break;
            default: {
                err = EPROTONOSUPPORT;
            } break;
        }
        
        if (err != 0) {
            [subscriber sendError:clientSocketError()];
        } else {
            CFSocketContext context = {0, (__bridge void *)(self), NULL, NULL, NULL};
            
            self.socket = (CFSocketRef) CFAutorelease( CFSocketCreateWithNative(NULL, fd, kCFSocketReadCallBack, SocketReadCallback, &context) );
            assert(self.socket != NULL);
            assert( CFSocketGetSocketFlags(self.socket) & kCFSocketCloseOnInvalidate);
            CFRunLoopSourceRef rls = CFSocketCreateRunLoopSource(kCFAllocatorDefault, self.socket, 0);
            assert(rls != NULL);
            
            CFRunLoopAddSource(CFRunLoopGetMain(), rls, kCFRunLoopDefaultMode);
            CFRelease(rls);
            [subscriber sendCompleted];
        }
        return nil;
        
    }] doError:^(NSError *error) {
        [self cleanSocket];
    }];
}

- (RACSignal *)singlePingSignalWithSequenceNumber:(uint16_t)sequenceNumber delay:(NSTimeInterval)delay{
    @weakify(self);
    return [RACSignal createSignal:^RACDisposable *(id<RACSubscriber> subscriber) {
        @strongify(self);
        RACDisposable *timeoutDisposable = [[RACScheduler scheduler]afterDelay:delay schedule:^{
            uexPingResult *result = [[uexPingResult alloc]initWithSequenceNumber:sequenceNumber];
            result.hostAddress = self.hostAddressString;
            result.hostName = self.hostName;
            NSData *packet = [self icmpPacketWithSequenceNumber:sequenceNumber];
            [self.pingResults setObject:result forKey:@(sequenceNumber)];
            @weakify(result);
            result.completionBlock = ^{
                @strongify(result);
                [subscriber sendNext:result];
                [subscriber sendCompleted];
            };
            if (!packet) {
                [result failWithError:clientICMPPacketError()];
                return;
            }
            if(!self.socket){
                [result failWithError:clientSocketError()];
                return;
            }
            ssize_t bytesSent = sendto(
                                       CFSocketGetNative(self.socket),
                                       packet.bytes,
                                       packet.length,
                                       0,
                                       self.hostAddress.bytes,
                                       (socklen_t) self.hostAddress.length
                                       );
            
            
            if (bytesSent < 0) {
                result.state = uexPingStateFailure;
                [result failWithError:clientSocketError()];
                return;
            }
            [[RACScheduler scheduler]afterDelay:self.pingTimeout schedule:^{
                @strongify(result);
                [result timeout];
            }];
            [self.disposeSignal subscribeNext:^(id x) {
                [result failWithError:clientDisposedError()];
            }];
        }];
        [self.disposeSignal subscribeNext:^(id x) {
            [timeoutDisposable dispose];
        }];
        return nil;
    }];
}

- (RACSignal *)pingSignal{
    @weakify(self)
    return [RACSignal createSignal:^RACDisposable *(id<RACSubscriber> subscriber) {
        @strongify(self);
        
        NSMutableArray<RACSignal *> *pings = [NSMutableArray array];
        for (uint16_t seqNumber = 1; seqNumber < self.pingTimes + 1; seqNumber ++) {
            RACSignal *singlePing = [self singlePingSignalWithSequenceNumber:seqNumber delay:(self.pingInterval * seqNumber)];
            [pings addObject:singlePing];
        }
        
        RACDisposable *disposable = [[RACSignal
           merge:pings]
           subscribeNext:^(uexPingResult *result) {
               [subscriber sendNext:result];
           }
           completed:^{
               [self.pingResults removeAllObjects];
               [subscriber sendCompleted];
           }];
        [self.disposeSignal subscribeNext:^(id x) {
            [disposable dispose];
            [subscriber sendError:clientDisposedError()];
        }];
        return [RACDisposable disposableWithBlock:^{
            [self cleanSocket];
        }];
    }];
}




@end


