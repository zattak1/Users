<?php

function Users_resend_post()
{
	$identifier = Users::requestedIdentifier($type);
	if ($type !== 'email' and $type !== 'mobile') {
		throw new Q_Exception("Expecting a valid email or mobile number", array('identifier', 'emailAddress', 'mobileNumber'));
	}
	if ($type === 'email') {
		$thing = 'email address';
		$field = 'emailAddress';
		$row = new Users_Email();
		$row->address = $identifier;
	} else if ($type === 'mobile') {
		$thing = 'mobile number';
		$field = 'mobileNumber';
		$row = new Users_Mobile();
		$row->number = $identifier;
	} else {
		throw new Q_Exception("Expecting a valid email or mobile number", array('identifier', 'emailAddress', 'mobileNumber'));
	}
	
	if ($row->retrieve()) {
		$userId = $row->userId;
	} else if ($ui = Users::identify($type, $identifier, 'future')) {
		$userId = $ui->userId;
	} else {
		throw new Q_Exception("That $thing was not found in the system", array('identifier', $field));
	}
	$user = new Users_User();
	$user->id = $userId;
	if (!$user->retrieve()) {
		throw new Q_Exception("No user corresponds to that $thing", array('identifier', $field));
	}
	$logged_in_user = Users::loggedInUser();
	if ($logged_in_user and $logged_in_user->id != $user->id) {
		throw new Q_Exception("That $thing belongs to someone else", array('identifier', $field));
	}
	// A verified address that is not the account's current one (kept from
	// before ro#939 retired replaced identifiers) must not become a way in for
	// a logged-out caller: activating its code would log them in. Same answer
	// as an unknown address, so this does not reveal which addresses exist.
	if (!$logged_in_user and !empty($row->userId) and $row->state !== 'unverified') {
		$current = ($type === 'email') ? $user->emailAddress : $user->mobileNumber;
		$here = ($type === 'email') ? $row->address : $row->number;
		if (strtolower(trim((string)$current)) !== strtolower(trim((string)$here))) {
			throw new Q_Exception("That $thing was not found in the system", array('identifier', $field));
		}
	}
	if ($type === 'email') {
		$existing = $user->addEmail($identifier);
		$user->save();
		Users::$cache['emailAddress'] = $identifier;
	} else {
		$existing = $user->addMobile($identifier);
		$user->save();
		Users::$cache['mobileNumber'] = $identifier;
	}
	if ($existing) {
		$existing->resendActivationMessage();
	}
	Users::$cache['user'] = $user;
	// Q_Response::setSlot('activateLink', Users::$cache['Users/activate link']);
}
