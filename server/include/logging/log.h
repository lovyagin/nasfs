/* server/include/logging/log.h -- Logging facilities interface
   Copyright (C) 2025 Nikita Morozov (@NikitosKey)

   This file is part of NASFS server.
   Defines logging functions and log levels for the server.  */

#ifndef LOG_H
#define LOG_H

#include <stdarg.h>

/* Log levels in order of increasing severity.  */
typedef enum log_level {
  LOG_DEBUG = 0,   /* Debug messages for development and troubleshooting */
  LOG_INFO = 1,    /* Informational messages for normal operation */
  LOG_WARNING = 2, /* Warning messages for potential issues */
  LOG_ERROR = 3,   /* Error messages for operational failures */
} log_level_t;

/* Initialize the logging module.
   LOG_PATH specifies the file to write logs to.
   MIN_LEVEL sets the minimum level of messages to be logged.  */
void log_init(const char *log_path, log_level_t min_level);

/* Write a log message to a stream.
   Formats a log message with variable arguments and writes it to STREAM.
   LEVEL indicates the severity of the message.
   FORMAT is a printf-style format string followed by arguments.  */
void log_stream(void *stream, log_level_t level, const char *format, ...);

/* Write a log message to a stream using a va_list.
   Like log_stream, but with a va_list instead of variable arguments.
   Useful for wrapper functions that need to pass on variable arguments.  */
void log_stream_v(void *stream, log_level_t level, const char *format,
                  va_list args);

/* Write a log message to the log file.
   Formats and writes a message with the specified LEVEL and FORMAT
   to the configured log file.  */
void log_file(log_level_t level, const char *format, ...);

/* Write a log message to stdout.
   Formats and writes a message with the specified LEVEL and FORMAT
   to standard output.  */
void log_stdout(log_level_t level, const char *format, ...);

/* Write a log message to both stdout and the log file.
   Formats and writes a message with the specified LEVEL and FORMAT
   to both standard output and the configured log file.  */
void log_all(log_level_t level, const char *format, ...);

#endif /* LOG_H */
