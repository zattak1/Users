<?php

/**
 * @module Users
 */

/**
 * Authorization for unsubscribe links, WITHOUT logging anyone in.
 *
 * An unsubscribe link has to work for someone who isn't logged in — that's the
 * point of it, and bulk-sender rules require it. The previous approach called
 * Users::setLoggedInUser(), which turned every unsubscribe link into a
 * password-equivalent: anyone holding the link — a forwarded email, a shared
 * screenshot, a mail client prefetching urls — got a full session as that user.
 *
 * Instead this grants exactly one capability: unsubscribe THIS identifier.
 * It's recorded in the session, scoped to that one address or number, expires
 * on its own, and is cleared after use. The visitor stays logged out.
 *
 * @class Users_Unsubscribe
 */
class Users_Unsubscribe
{
	/**
	 * How long a grant lasts, in seconds.
	 * @method duration
	 * @static
	 * @return {integer}
	 */
	static function duration()
	{
		return Q_Config::get('Users', 'unsubscribe', 'grant', 'duration', 3600);
	}

	/**
	 * Look at the current request for a valid unsubscribe link, and if there is
	 * one, record a scoped grant in the session.
	 *
	 * Accepts every parameter spelling the codebase generates, because links
	 * already sitting in inboxes can't be reissued:
	 *
	 *   Users/User.php      ?authCode=..&e=<address>
	 *   Users/Email.php     ?authCode=..&emailAddress=<address>
	 *   Users/Mobile.php    ?authCode=..&mobileNumber=<number>
	 *   views/addEmail.php  ?code=<authCode>            (no identifier)
	 *
	 * @method fromRequest
	 * @static
	 * @return {array|null} The grant that was stored, if any
	 */
	static function fromRequest()
	{
		$authCode = Q::ifset($_REQUEST, 'authCode', Q::ifset($_REQUEST, 'code', null));
		if (empty($authCode)) {
			return null; // nothing to verify against
		}

		$mobileNumber = Q::ifset($_REQUEST, 'mobileNumber', null);
		if (!empty($mobileNumber)) {
			return self::verify('mobile', $mobileNumber, $authCode);
		}

		$address = Q::ifset($_REQUEST, 'e',
			Q::ifset($_REQUEST, 'emailAddress', null)
		);
		if (!empty($address)) {
			return self::verify('email', $address, $authCode);
		}

		// a generic "identifier" could be either, so try both rather than
		// guessing from its shape
		$identifier = Q::ifset($_REQUEST, 'identifier', null);
		if (!empty($identifier)) {
			$grant = self::verify('email', $identifier, $authCode);
			return $grant ? $grant : self::verify('mobile', $identifier, $authCode);
		}

		// the ?code= form carries no identifier at all, so find the row by code
		$grant = self::byAuthCode('email', $authCode);
		return $grant ? $grant : self::byAuthCode('mobile', $authCode);
	}

	/**
	 * Check an identifier's authCode and, if it matches, issue a grant.
	 * @method verify
	 * @static
	 * @param {string} $type "email" or "mobile"
	 * @param {string} $identifier
	 * @param {string} $authCode
	 * @return {array|null}
	 */
	static function verify($type, $identifier, $authCode)
	{
		if ($type === 'mobile') {
			$row = new Users_Mobile();
			$row->number = $identifier;
		} else {
			$row = new Users_Email();
			$row->address = $identifier;
		}
		if (!$row->retrieve()) {
			return null;
		}
		return self::matched($type, $row, $identifier, $authCode);
	}

	/**
	 * Find the row whose authCode this is, for links that carry no identifier.
	 * @method byAuthCode
	 * @static
	 * @param {string} $type "email" or "mobile"
	 * @param {string} $authCode
	 * @return {array|null}
	 */
	static function byAuthCode($type, $authCode)
	{
		if ($type === 'mobile') {
			$row = Users_Mobile::select()
				->where(array('authCode' => $authCode))->limit(1)->fetchDbRow();
			$identifier = $row ? $row->number : null;
		} else {
			$row = Users_Email::select()
				->where(array('authCode' => $authCode))->limit(1)->fetchDbRow();
			$identifier = $row ? $row->address : null;
		}
		if (!$row) {
			return null;
		}
		return self::matched($type, $row, $identifier, $authCode);
	}

	/**
	 * Constant-time comparison, refusing rows with an empty authCode.
	 * @method matched
	 * @static
	 * @protected
	 * @param {string} $type
	 * @param {Db_Row} $row
	 * @param {string} $identifier
	 * @param {string} $authCode
	 * @return {array|null}
	 */
	protected static function matched($type, $row, $identifier, $authCode)
	{
		$stored = (string)Q::ifset($row, 'authCode', '');
		if ($stored === '' or !hash_equals($stored, (string)$authCode)) {
			return null;
		}
		return self::grant($type, $identifier, $row->userId);
	}

	/**
	 * Record a grant in the session.
	 * @method grant
	 * @static
	 * @param {string} $type "email" or "mobile"
	 * @param {string} $identifier The address or number it applies to
	 * @param {string} $userId
	 * @return {array}
	 */
	static function grant($type, $identifier, $userId)
	{
		if (empty($userId)) {
			return null; // an identifier not attached to anyone
		}
		$grant = array(
			'type' => $type,
			'identifier' => $identifier,
			'userId' => $userId,
			'expires' => time() + self::duration()
		);
		Q_Session::setNonce();
		$_SESSION['Users']['unsubscribe'] = $grant;
		return $grant;
	}

	/**
	 * Whether the session holds a live grant for exactly this identifier.
	 *
	 * The identifier is compared, not merely checked for existence: a grant for
	 * one address must not unsubscribe another, or a leaked link for a
	 * throwaway address would let someone silence the account's real one.
	 *
	 * @method authorize
	 * @static
	 * @param {string} $type
	 * @param {string} $identifier
	 * @return {string|null} The userId this authorizes, or null
	 */
	static function authorize($type, $identifier)
	{
		$grant = Q::ifset($_SESSION, 'Users', 'unsubscribe', null);
		if (!is_array($grant)) {
			return null;
		}
		if (Q::ifset($grant, 'expires', 0) < time()) {
			unset($_SESSION['Users']['unsubscribe']);
			return null;
		}
		if (Q::ifset($grant, 'type', null) !== $type) {
			return null;
		}
		if (!hash_equals(
			(string)Q::ifset($grant, 'identifier', ''), (string)$identifier
		)) {
			return null;
		}
		return Q::ifset($grant, 'userId', null);
	}

	/**
	 * Drop the grant, once it has been used.
	 * @method clear
	 * @static
	 */
	static function clear()
	{
		unset($_SESSION['Users']['unsubscribe']);
	}
}
