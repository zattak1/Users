<?php

function Users_activate_response_content()
{
	$email = $mobile = $type = $user = $emailAddress = $mobileNumber = null;
	extract(Users::$cache, EXTR_IF_EXISTS);

	$complete = false;
	if ($user and !empty($user->passphraseHash)) {
		if ($emailAddress and $user->emailAddress == $emailAddress) {
			$complete = true;
		} else if ($mobileNumber and $user->mobileNumber == $mobileNumber) { // was =, ro#957
			$complete = true;
		}
	}
	
	$app = Q::app();
	$successUrl = Q::ifset($_REQUEST, 'successUrl',
		Q_Config::get('Users', 'uris', "$app/successUrl", "$app/home")
	);
	$appendFields = array();
	foreach ($_GET as $k => $v) {
		$substr = substr($k, 0, 2);
		if ($substr !== 'Q_' && $substr !== 'Q.') {
			$appendFields[$k] = $v;
		}
	}
	$afterActivate = Q::ifset($_REQUEST, 'afterActivate',
		Q_Config::get('Users', 'uris', "$app/afterActivate", $successUrl)
	) .'?Q.fromSuccess=Users/activate';

	if (!empty(Users::$cache['success'])
	and Q_Request::method() === 'POST') {
		$afterActivate = Q_Uri::fixUrl(Q::interpolate($afterActivate, array(
			'email' => $emailAddress ? urlencode($emailAddress) : '',
			'mobile' => $mobileNumber ? urlencode($mobileNumber) : ''
		)));
		Q_Response::redirect($afterActivate);
		return true;
	}
	
	$view = Q_Config::get('Users', 'activateView', 'Users/content/activate.php');
	$t = $email ? 'e' : 'm';
	$autocompleteType = $email ? 'email' : 'phone';
	$identifier = $email ? $emailAddress : $mobileNumber;

	// Generate 10 passphrase suggestions (fallback)
	$suggestions = array();
	$arr = include(USERS_PLUGIN_FILES_DIR.DS.'passphrases.php');
	for ($i=0; $i<10; ++$i) {
		$pre1 = $arr['pre'][random_int(0, count($arr['pre'])-1)];
		$noun1 = $arr['nouns'][random_int(0, count($arr['nouns'])-1)];
		$verb = $arr['verbs'][random_int(0, count($arr['verbs'])-1)];
		$pre2 = $arr['pre'][random_int(0, count($arr['pre'])-1)];
		$noun2 = $arr['nouns'][random_int(0, count($arr['nouns'])-1)];
		$suggestions[] = strtolower("$pre1 $noun1 $verb $pre2 $noun2");
	}
	$verb_ue = urlencode($arr['verbs'][random_int(0, count($arr['verbs']) - 1)]);
	$noun_ue = urlencode($arr['nouns'][random_int(0, count($arr['nouns']) - 1)]);
	$code = Q::ifset($_REQUEST, 'code', null);
	
	// The suggestions above are the only ones offered. Upstream replaced them
	// with three-word windows of NewsAPI headlines when Users/newsapi/key was
	// set: an enumerable set of public text picked with rand(), offered as an
	// account passphrase (ro#732, Codex audit R01).
	
	$salt_json = Q::json_encode($user ? $user->salt : '');

	return Q::view($view, @compact(
		'identifier', 'type', 'user', 'code', 'afterActivate',
		'suggestions', 'verb_ue', 'noun_ue', 't', 'autocompleteType', 'app', 'home', 'complete', 'salt_json'
	));
}