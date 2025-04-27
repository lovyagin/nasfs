/* server/src/logging/log.c -- Logging module for the server
   Copyright (C) 2025  Nikita Morozov (@NikitosKey)


   This file is part of NASFS server.  */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "logging/log.h"

static char *log_path_saved;
static log_level_t min_level_saved;

/* Initialize the logging module.
   Opens the log file at LOG_PATH and sets the minimum log level to MIN_LEVEL.
   If the log file cannot be opened, logs a warning to stderr and stdout.  */
void
log_init (const char *log_path, log_level_t min_level)
{
  FILE *log_file = fopen (log_path, "a");
  if (!log_file)
    {
      fprintf (stderr, "Failed to open log file '%s'\n", log_path);
      fprintf (stdout, "WARNING!!! Logging only to stdout\nTo fix this "
                       "issue, ensure that the log file path is correct "
                       "and that the server has write permissions.\n");
    }
  min_level_saved = min_level;
  log_path_saved = strdup (log_path);
  fclose (log_file);
}

/* Convert a log level to its string representation.
   Returns a string corresponding to the given log level.  */
const char *
log_level_str (log_level_t level)
{
  switch (level)
    {
    case LOG_DEBUG:
      return "DEBUG";
    case LOG_INFO:
      return "INFO";
    case LOG_WARNING:
      return "WARNING";
    case LOG_ERROR:
      return "ERROR";
    default:
      fprintf (stderr, "Invalid log level %d\n", level);
      return "UNKNOWN";
    }
}

/* Write a log message to a stream.
   Formats a log message and writes it to the given STREAM with the specified
   LEVEL and FORMAT string, using variable arguments.  */
void
log_stream (void *stream, log_level_t level, const char *format, ...)
{
  va_list args;
  va_start (args, format);
  log_stream_v (stream, level, format, args);
  va_end (args);
}

/* Write a log message to a stream using a va_list.
   Formats a log message and writes it to the given STREAM with the specified
   LEVEL, FORMAT string, and variable argument list ARGS.
   Only logs if the current log level is at least as severe as LEVEL.  */
void
log_stream_v (void *stream, log_level_t level, const char *format,
              va_list args)
{
  if (level >= min_level_saved)
    {
      time_t now = time (NULL);
      struct tm local_time;
      localtime_r (&now, &local_time);
      char timestamp[64];
      strftime (timestamp, sizeof (timestamp), "%Y-%m-%d %H:%M:%S %z",
                &local_time);
      fprintf (stream, "[PID=%u %s] %s ", getpid (), timestamp,
               log_level_str (level));

      vfprintf (stream, format, args);
      fprintf (stream, "\n");
    }
}

/* Write a log message to the log file.
   Formats and writes a message with the specified LEVEL and FORMAT
   to the configured log file.  */
void
log_file (log_level_t level, const char *format, ...)
{
  FILE *log_file = fopen (log_path_saved, "a");
  if (log_file == NULL)
    return;
  va_list args;
  va_start (args, format);
  log_stream_v (log_file, level, format, args);
  va_end (args);
  fclose (log_file);
}

/* Write a log message to stdout.
   Formats and writes a message with the specified LEVEL and FORMAT
   to standard output.  */
void
log_stdout (log_level_t level, const char *format, ...)
{
  va_list args;
  va_start (args, format);
  log_stream_v (stdout, level, format, args);
  va_end (args);
  fprintf (stdout, "\n");
}

/* Write a log message to both stdout and the log file.
   Formats and writes a message with the specified LEVEL and FORMAT
   to both standard output and the configured log file.  */
void
log_all (log_level_t level, const char *format, ...)
{
  va_list args_stdout, args_file;
  va_start (args_stdout, format);
  va_copy (args_file, args_stdout);

  log_stream_v (stdout, level, format, args_stdout);

  FILE *log_file = fopen (log_path_saved, "a");
  if (log_file != NULL)
    {
      log_stream_v (log_file, level, format, args_file);
      fclose (log_file);
    }

  va_end (args_file);
  va_end (args_stdout);
}
