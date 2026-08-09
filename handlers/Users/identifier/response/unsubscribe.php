<?php

/**
 * Unsubscribes an identifier.
 *
 * Works either for a logged-in user, or for someone who arrived on an
 * unsubscribe link and holds a scoped grant for exactly this identifier.
 * The grant is NOT a login: it authorizes this one action, on this one
 * address, and nothing else. See Users_Unsubscribe.
 */
function Users_identifier_response_unsubscribe($params)
{
	Q_Valid::nonce(true);

	$r = array_merge($_REQUEST, $params);
	$fields = Q::take($r, array('identifier', 'type'));
	$identifier = $fields['identifier'];
	$type = $fields['type'];

	$user = Users::loggedInUser(false);
	$userId = $user ? $user->id : null;
	$byGrant = false;

	if (!$userId) {
		// no session — fall back to an unsubscribe grant, which is scoped
		// to this exact identifier, so a link for one address can't be used
		// to unsubscribe another
		$userId = Users_Unsubscribe::authorize($type, $identifier);
		$byGrant = true;
	}

	if (!$userId) {
		throw new Users_Exception_NotLoggedIn();
	}

	if ($type == 'email') {
		Users_Email::update()->set(array(
			'state' => 'unsubscribed'
		))->where(array(
			'userId' => $userId,
			'address' => $identifier,
			'state!=' => 'unverified'
		))->execute();
		$res = Users_Email::select()->where(array('userId' => $userId, 'address' => $identifier))->fetchDbRow();
		$res = Q::ifset($res, 'state', null);
	} elseif ($type == 'mobile') {
		Users_Mobile::update()->set(array(
			'state' => 'unsubscribed'
		))->where(array(
			'userId' => $userId,
			'number' => $identifier,
			'state!=' => 'unverified'
		))->execute();
		$res = Users_Mobile::select()->where(array('userId' => $userId, 'number' => $identifier))->fetchDbRow();
		$res = Q::ifset($res, 'state', null);
	}

	if ($byGrant) {
		Users_Unsubscribe::clear(); // one use is all it was for
	}

	return $res;
}
