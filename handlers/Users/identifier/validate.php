<?php

// This was defined as Users_contact_validate, so Q_validate (which looks up
// "Users/identifier/validate") never ran it: Users/identifier POST and DELETE,
// which add and remove login identifiers, went without a nonce check (ro#940).
// Its body also fired Users/user/validate, the login-lookup validator, which
// would reject adding a new address under Users/login/noRegister; that call
// never ran, so it is left out rather than switched on. GET slots (data,
// contact, form...) are reads and keep working without a nonce.
function Users_identifier_validate()
{
	if (Q_Request::method() !== 'GET') {
		Q_Valid::nonce(true);
	}
}
