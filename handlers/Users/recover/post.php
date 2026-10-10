<?php

/**
 * Session recovery with a previously registered recovery key: REFUSED.
 *
 * This endpoint fails closed until session recovery is redesigned (ro#860).
 * Every request is rejected after the origin check, before anything reads the
 * request body, the database or the session. The handler it replaces could
 * never work, and the one part that could have started working was the
 * dangerous part:
 *
 * - It never verified the recovery signature. Its docblock said the
 *   signed-request middleware did, but Users_before_Q_objects() verifies only
 *   when the *current* session already has a publicKey and a
 *   Users/requireLogin rule matches the URI; a recovering session has no key,
 *   and no rule names this URI. So once resumption worked, the recovery
 *   *public* JWK (stored in $_SESSION, in the intent's instructions, and
 *   returned to the opener by Users/intent) would have been a bearer
 *   credential for the original session.
 * - Step 3 could not resume the session. The dispatcher starts the session
 *   before any handler (Q/session/startBefore is Q/reroute), PHP >= 7.2
 *   refuses session_id($id) on an active session, and Q_Session::start()
 *   without $setId returns false once an id exists, so the handler always
 *   threw "Could not resume session". Q_Dispatcher::errors() sends no cookie
 *   on that path either.
 * - The client and this handler disagree on the request. recover.js sends
 *   recoveryKey at the top level, with Q_Users_sig = {signature (hex raw
 *   r||s), publicKey (hex SPKI), fieldNames}; the handler required
 *   Q_Users_sig[recoveryKey], which no client sends, and Q_Data::verify()
 *   base64-decodes its public keys, so Users::verify() cannot check a key in
 *   the hex form Users.sign() produces.
 *
 * Making recovery work therefore means a design decision (adopt the old
 * session id, or log the current session in as the original session's user
 * the way Users_Intent::accept() does), an agreed wire format, and a
 * server-side check that the request is signed by the private half of the
 * very recoveryKey being presented. Until that exists, refusing is the only
 * behaviour that cannot be abused. No page in our apps reaches this endpoint:
 * Users.Session.recover() runs only on a Q.Users.recoveryKey.recover message
 * from a parent frame.
 *
 * Users_key_post still registers recovery keys and writes the
 * Users/registerRecoveryKey intent; nothing consumes it while this refuses.
 *
 * @method Users_recover_post
 * @throws Q_Exception_WrongValue when the request is cross-origin
 * @throws Q_Exception_NotImplemented always, otherwise
 */
function Users_recover_post()
{
	// Q_Request::requireOrigin($throwIfInvalid), not Q_Valid::requireOrigin($url, ...):
	// passing true to the latter sets $url and leaves the check non-throwing.
	Q_Request::requireOrigin(true);

	// Fail closed (ro#860): see the docblock. Do not restore a resume path
	// here without verifying, in this handler, that the request is signed by
	// the private key matching the presented recoveryKey.
	throw new Q_Exception_NotImplemented(array(
		'functionality' => 'Users/recover (session recovery is disabled)'
	));
}
