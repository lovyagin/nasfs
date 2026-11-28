#ifndef NASFS_SESSION_INTERNAL_H
#define NASFS_SESSION_INTERNAL_H

#include "network/session.h"

/* Transport callbacks for the file service, called only on the event loop. */
int session_send_frame(client_session_t* session, nasfs_cmd_type_t type,
                       const uint8_t* payload, size_t payload_len, int encrypt);
void session_finish_close(client_session_t* session);
void process_session_frames(client_session_t* session);
void session_resume_read(client_session_t* session);

#endif
