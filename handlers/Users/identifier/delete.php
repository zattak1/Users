<?php

function Users_identifier_delete()
{
	$user = Users::loggedInUser(true);
	$identifier = Users::requestedIdentifier($type);

	if (!$type) {
		throw new Q_Exception(
			"a valid email address or mobile number is required", 
			array('identifier', 'mobileNumber', 'emailAddress')
		);
	}

	// Removing the identifier the account signs in with is a credential event
	// (ro#548, audit R03). Read what it was reachable by first: once it is
	// removed the primary field is empty, and a later add would look like a
	// first registration and skip every safeguard.
	$previousEmail = isset($user->emailAddress) ? $user->emailAddress : null;
	$previousMobile = isset($user->mobileNumber) ? $user->mobileNumber : null;
	$wasPrimary = false;
	if ($type === 'email') {
		Q_Valid::email($identifier, $normalized);
		$wasPrimary = $previousEmail
			&& strtolower(trim($previousEmail)) === strtolower(trim($normalized));
	} else if ($type === 'mobile') {
		Q_Valid::phone($identifier, $normalized);
		$wasPrimary = $previousMobile && trim($previousMobile) === trim($normalized);
	}

	$user->removeIdentifier($identifier);

	if ($wasPrimary) {
		Users::identifierCredentialEvent(
			$user,
			$type === 'email' ? 'email address' : 'mobile number',
			$previousEmail,
			true,
			$previousMobile,
			'removed'
		);
	}
}
