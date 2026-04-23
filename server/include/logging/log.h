/**
 * @file log.h
 * @brief Logging facilities interface for the NASFS server.
 *
 * Copyright (C) 2025 Nikita Morozov (@NikitosKey)
 *
 * This file is part of NASFS server.
 * Defines logging functions and log levels for the server.
 */

#ifndef LOG_H
#define LOG_H

#include <stdarg.h>

/**
 * @enum log_level
 * @brief Represents the severity level of a log message.
 */
typedef enum log_level {
  LOG_DEBUG = 0,   /**< Debug messages for development and troubleshooting */
  LOG_INFO = 1,    /**< Informational messages for normal operation */
  LOG_WARNING = 2, /**< Warning messages for potential issues */
  LOG_ERROR = 3,   /**< Error messages for operational failures */
} log_level_t;

/**
 * @brief Initializes the logging module.
 *
 * @param log_path The file path where logs should be written.
 * @param min_level The minimum severity level to record.
 */
void log_init(const char* log_path, log_level_t min_level);

/**
 * @brief Writes a formatted log message to a specific stream.
 *
 * @param stream The output stream (e.g., stdout, stderr, or a file pointer).
 * @param level The severity level of the message.
 * @param format The printf-style format string.
 * @param ... Variable arguments for the format string.
 */
void log_stream(void* stream, log_level_t level, const char* format, ...);

/**
 * @brief Writes a log message to a stream using a va_list.
 *
 * @param stream The output stream.
 * @param level The severity level of the message.
 * @param format The printf-style format string.
 * @param args The variable arguments list.
 */
void log_stream_v(void* stream, log_level_t level, const char* format,
                  va_list args);

/**
 * @brief Writes a formatted log message to the configured log file.
 *
 * @param level The severity level of the message.
 * @param format The printf-style format string.
 * @param ... Variable arguments for the format string.
 */
void log_file(log_level_t level, const char* format, ...);

/**
 * @brief Writes a formatted log message to standard output.
 *
 * @param level The severity level of the message.
 * @param format The printf-style format string.
 * @param ... Variable arguments for the format string.
 */
void log_stdout(log_level_t level, const char* format, ...);

/**
 * @brief Writes a formatted log message to both standard output and the log
 * file.
 *
 * @param level The severity level of the message.
 * @param format The printf-style format string.
 * @param ... Variable arguments for the format string.
 */
void log_all(log_level_t level, const char* format, ...);

#endif /* LOG_H */