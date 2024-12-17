

#ifndef WOLFSSL_DEBUGGING_H
#define WOLFSSL_DEBUGGING_H

/* Log a message that has the printf format string.
 *
 * @param [in] <va_args>  printf style arguments.
 */
#define WOLFSSL_MSG_VSNPRINTF(...)                    \
    do {                                              \
      char line[81];                                  \
      snprintf(line, sizeof(line) - 1, __VA_ARGS__);  \
      line[sizeof(line) - 1] = '\0';                  \
      WOLFSSL_MSG(line);                              \
    }                                                 \
    while (0)

#define MADWOLF_DEBUG0(a)                         \
    do {                                              \
        printf("[%s:%d] %s(): " a "\n", __FILE__, __LINE__, __func__);      \
        fflush(stdout);                               \
    } while (0)


#define MADWOLF_DEBUG(a, ...)                         \
    do {                                              \
        printf("[%s:%d] %s(): " a "\n", __FILE__, __LINE__, __func__, __VA_ARGS__);      \
        fflush(stdout);                               \
    } while (0)

#endif /* WOLFSSL_DEBUGGING_H */