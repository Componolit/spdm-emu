/**
    Copyright Notice:
    Copyright 2021 DMTF, Componolit. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

#include <spdm_transport_none_lib.h>
#include <library/spdm_secured_message_lib.h>

/**
  Encode a normal message or secured message to a transport message.

  @param  session_id                    Indicates if it is a secured message protected via SPDM session.
                                       If session_id is NULL, it is a normal message.
                                       If session_id is NOT NULL, it is a secured message.
  @param  message_size                  size in bytes of the message data buffer.
  @param  message                      A pointer to a source buffer to store the message.
  @param  transport_message_size         size in bytes of the transport message data buffer.
  @param  transport_message             A pointer to a destination buffer to store the transport message.

  @retval RETURN_SUCCESS               The message is encoded successfully.
  @retval RETURN_INVALID_PARAMETER     The message is NULL or the message_size is zero.
**/
return_status none_encode_message(IN uint32 *session_id, IN uintn message_size,
				  IN void *message,
				  IN OUT uintn *transport_message_size,
				  OUT void *transport_message);

/**
  Decode a transport message to a normal message or secured message.

  @param  session_id                    Indicates if it is a secured message protected via SPDM session.
                                       If *session_id is NULL, it is a normal message.
                                       If *session_id is NOT NULL, it is a secured message.
  @param  transport_message_size         size in bytes of the transport message data buffer.
  @param  transport_message             A pointer to a source buffer to store the transport message.
  @param  message_size                  size in bytes of the message data buffer.
  @param  message                      A pointer to a destination buffer to store the message.
  @retval RETURN_SUCCESS               The message is encoded successfully.
  @retval RETURN_INVALID_PARAMETER     The message is NULL or the message_size is zero.
**/
return_status none_decode_message(OUT uint32 **session_id,
				  IN uintn transport_message_size,
				  IN void *transport_message,
				  IN OUT uintn *message_size,
				  OUT void *message);

/**
  Encode a normal message or secured message to a transport message.

  @param  session_id                    Indicates if it is a secured message protected via SPDM session.
                                       If session_id is NULL, it is a normal message.
                                       If session_id is NOT NULL, it is a secured message.
  @param  message_size                  size in bytes of the message data buffer.
  @param  message                      A pointer to a source buffer to store the message.
  @param  transport_message_size         size in bytes of the transport message data buffer.
  @param  transport_message             A pointer to a destination buffer to store the transport message.

  @retval RETURN_SUCCESS               The message is encoded successfully.
  @retval RETURN_INVALID_PARAMETER     The message is NULL or the message_size is zero.
**/
typedef return_status (*transport_encode_message_func)(
	IN uint32 *session_id, IN uintn message_size, IN void *message,
	IN OUT uintn *transport_message_size, OUT void *transport_message);

/**
  Decode a transport message to a normal message or secured message.

  @param  session_id                    Indicates if it is a secured message protected via SPDM session.
                                       If *session_id is NULL, it is a normal message.
                                       If *session_id is NOT NULL, it is a secured message.
  @param  transport_message_size         size in bytes of the transport message data buffer.
  @param  transport_message             A pointer to a source buffer to store the transport message.
  @param  message_size                  size in bytes of the message data buffer.
  @param  message                      A pointer to a destination buffer to store the message.
  @retval RETURN_SUCCESS               The message is encoded successfully.
  @retval RETURN_INVALID_PARAMETER     The message is NULL or the message_size is zero.
**/
typedef return_status (*transport_decode_message_func)(
	OUT uint32 **session_id, IN uintn transport_message_size,
	IN void *transport_message, IN OUT uintn *message_size,
	OUT void *message);

/**
  Encode an SPDM or APP message to a transport layer message.

  For normal SPDM message, it adds the transport layer wrapper.
  For secured SPDM message, it encrypts a secured message then adds the transport layer wrapper.
  For secured APP message, it encrypts a secured message then adds the transport layer wrapper.

  The APP message is encoded to a secured message directly in SPDM session.
  The APP message format is defined by the transport layer.
  Take MCTP as example: APP message == MCTP header (MCTP_MESSAGE_TYPE_SPDM) + SPDM message

  @param  spdm_context                  A pointer to the SPDM context.
  @param  session_id                    Indicates if it is a secured message protected via SPDM session.
                                       If session_id is NULL, it is a normal message.
                                       If session_id is NOT NULL, it is a secured message.
  @param  is_app_message                 Indicates if it is an APP message or SPDM message.
  @param  is_requester                  Indicates if it is a requester message.
  @param  message_size                  size in bytes of the message data buffer.
  @param  message                      A pointer to a source buffer to store the message.
  @param  transport_message_size         size in bytes of the transport message data buffer.
  @param  transport_message             A pointer to a destination buffer to store the transport message.

  @retval RETURN_SUCCESS               The message is encoded successfully.
  @retval RETURN_INVALID_PARAMETER     The message is NULL or the message_size is zero.
**/

static uint32 *msg_session_id;

return_status spdm_transport_none_encode_message(
	IN void *spdm_context, IN uint32 *session_id, IN boolean is_app_message,
	IN boolean is_requester, IN uintn message_size, IN void *message,
	IN OUT uintn *transport_message_size, OUT void *transport_message)
{
	return_status status;
	transport_encode_message_func transport_encode_message;

	transport_encode_message = none_encode_message;
        // SPDM message to normal MCTP message
        status = transport_encode_message(NULL, message_size, message,
                                          transport_message_size,
                                          transport_message);
        msg_session_id = session_id;
        if (RETURN_ERROR(status)) {
                DEBUG((DEBUG_ERROR, "transport_encode_message - %p\n",
                       status));
                return RETURN_UNSUPPORTED;
        }

	return RETURN_SUCCESS;
}

/**
  Decode an SPDM or APP message from a transport layer message.

  For normal SPDM message, it removes the transport layer wrapper,
  For secured SPDM message, it removes the transport layer wrapper, then decrypts and verifies a secured message.
  For secured APP message, it removes the transport layer wrapper, then decrypts and verifies a secured message.

  The APP message is decoded from a secured message directly in SPDM session.
  The APP message format is defined by the transport layer.
  Take MCTP as example: APP message == MCTP header (MCTP_MESSAGE_TYPE_SPDM) + SPDM message

  @param  spdm_context                  A pointer to the SPDM context.
  @param  session_id                    Indicates if it is a secured message protected via SPDM session.
                                       If *session_id is NULL, it is a normal message.
                                       If *session_id is NOT NULL, it is a secured message.
  @param  is_app_message                 Indicates if it is an APP message or SPDM message.
  @param  is_requester                  Indicates if it is a requester message.
  @param  transport_message_size         size in bytes of the transport message data buffer.
  @param  transport_message             A pointer to a source buffer to store the transport message.
  @param  message_size                  size in bytes of the message data buffer.
  @param  message                      A pointer to a destination buffer to store the message.

  @retval RETURN_SUCCESS               The message is decoded successfully.
  @retval RETURN_INVALID_PARAMETER     The message is NULL or the message_size is zero.
  @retval RETURN_UNSUPPORTED           The transport_message is unsupported.
**/

return_status spdm_transport_none_decode_message(
	IN void *spdm_context, OUT uint32 **session_id,
	OUT boolean *is_app_message, IN boolean is_requester,
	IN uintn transport_message_size, IN void *transport_message,
	IN OUT uintn *message_size, OUT void *message)
{
	return_status status;
	transport_decode_message_func transport_decode_message;
	uint32 *SecuredMessageSessionId;
	spdm_error_struct_t spdm_error;

	spdm_error.error_code = 0;
	spdm_error.session_id = 0;
	spdm_set_last_spdm_error_struct(spdm_context, &spdm_error);

	if ((session_id == NULL) || (is_app_message == NULL)) {
		return RETURN_UNSUPPORTED;
	}

	transport_decode_message = none_decode_message;

        // get non-secured message
        status = transport_decode_message(&SecuredMessageSessionId,
                                          transport_message_size,
                                          transport_message,
                                          message_size, message);
        if (RETURN_ERROR(status)) {
                DEBUG((DEBUG_ERROR, "transport_decode_message - %p\n",
                       status));
                return RETURN_UNSUPPORTED;
        }
        *session_id = msg_session_id;
        *is_app_message = FALSE;
        return RETURN_SUCCESS;
}
