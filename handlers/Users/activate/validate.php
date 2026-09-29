<?php

function Users_activate_validate()
{
	$uri = Q_Dispatcher::uri();
	$emailAddress = Q::ifset($_REQUEST, 'e', Q::ifset($_REQUEST, 'emailAddress', $uri->emailAddress));
	$mobileNumber = Q::ifset($_REQUEST, 'm', Q::ifset($_REQUEST, 'mobileNumber', $uri->mobileNumber));
	if ($emailAddress && !Q_Valid::email($emailAddress, $e_normalized, array('no_ip' => 'false'))) {
		throw new Q_Exception_WrongValue(array(
			'field' => 'email',
			'range' => 'a valid email address'
		), 'emailAddress');
	}
	if ($mobileNumber && !Q_Valid::phone($mobileNumber, $m_normalized)) {
		throw new Q_Exception_WrongValue(array(
			'field' => 'mobile phone',
			'range'	=> 'a valid phone number'
		), 'mobileNumber');
	}
	// ro#917: a JSON body reaches $_REQUEST with its types intact, so "code": true
	// is non-empty and loosely equals any stored code. Only a string or integer
	// can be a code; reject everything else before any comparison.
	if (isset($_REQUEST['code']) and !is_string($_REQUEST['code']) and !is_int($_REQUEST['code'])) {
		throw new Q_Exception_WrongType(array(
			'field' => 'code',
			'type' => 'string'
		), 'code');
	}
	if (Q_Request::method() === 'POST' and empty($_REQUEST['code'])) {
		Q_Response::addError(
			new Q_Exception("The activation code is required")
		);
	}
	if (!$emailAddress and !$mobileNumber) {
		throw new Q_Exception("The email address or mobile number is required");
	}
	if (!empty($e_normalized)) {
		Users::$cache['emailAddress'] = $e_normalized;
	}
	if (!empty($m_normalized)) {
		Users::$cache['mobileNumber'] = $m_normalized;
	}
}
