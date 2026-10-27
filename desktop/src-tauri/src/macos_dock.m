#import <Cocoa/Cocoa.h>

void locksmith_set_dock_icon(const unsigned char *bytes, unsigned long len) {
    @autoreleasepool {
        NSData *data = [NSData dataWithBytes:bytes length:len];
        NSImage *image = [[NSImage alloc] initWithData:data];
        if (image) {
            [NSApp setApplicationIconImage:image];
        }
    }
}
