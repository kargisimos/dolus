#ifndef DEBUG_H
#define DEBUG_H

//uncomment next line to enable debugging
#define DEBUG 1
#ifdef DEBUG
#define DEBUG_INFO(...) do { \
    printk(KERN_INFO __VA_ARGS__); \
} while (0)
#else
#define DEBUG_INFO(...) do {} while (0)
#endif



#endif