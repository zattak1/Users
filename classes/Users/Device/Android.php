<?php

class Users_Device_Android extends Users_Device
{

	/**
	 * You can use this method to send push notifications.
	 * It is far better, however, to use the Qbix Platform's offline notification
	 * mechanisms using Node.js instead of PHP. That way, you can be sure of re-using
	 * the same persistent connection.
	 * @method pushNotification
	 * @param {array} $notification See Users_Device->pushNotification parameters
	 * @param {array} [$options] See Users_Device->pushNotification parameters
	 */
	function handlePushNotification($notification, $options = array())
	{
		if (is_string($notification['alert'])) {
			$notification['alert'] = array(
				'title' => Users::communityName(),
				'body' => $notification['alert']
			);
		}
		self::$push[] = array(
			'title' => $notification['alert']['title'],
			'body' => $notification['alert']['body'],
			'icon' => empty($notification['icon']) ? '' : $notification['icon'],
			'click_action' => empty($notification['url']) ? null : $notification['url'],
			'sound' => empty($notification['sound']) ? 'default' : $notification['sound']
		);
		self::$device = $this;
		self::sendPushNotifications();
	}

	/**
	 * Sends all scheduled push notifications
	 * @method sendPushNotifications
	 * @static
	 * @throws Users_Exception_DeviceNotification
	 */
	static function sendPushNotifications()
	{
		if (!self::$push) {
			return;
		}
		// Fail closed (ro#812). This posts to FCM's legacy HTTP API
		// (fcm/send with a server key), which Google deprecated on 2023-06-20
		// and shut down from 2024-07-22 in favour of HTTP v1 (OAuth2
		// service-account tokens, /v1/projects/<id>/messages:send). Every
		// request below now fails, and nothing reads curl's result, so the
		// notification used to vanish without a trace. Refuse loudly instead,
		// before reading the key or opening a connection, and drop the queue
		// so a later call does not retry it. Remove this only together with
		// a port to HTTP v1.
		self::$push = [];
		throw new Users_Exception_DeviceNotification(array(
			'statusMessage' => 'the FCM legacy HTTP API (fcm/send) has been shut down by Google;'
				. ' PHP-side Android push needs a port to FCM HTTP v1'
		));
		$apiKey = Q_Config::expect('Users', 'apps', 'android', Q::app(), "key");
		// A push notification must never be able to outlive the request that
		// triggered it. curl's default CURLOPT_TIMEOUT is 0 = infinite, so
		// without these one unresponsive FCM endpoint holds a php-fpm worker
		// until something outside PHP kills it -- in ro that is the #581 cap
		// (request_terminate_timeout 45s wall-clock), which SIGTERMs the worker
		// mid-loop with some notifications sent and no record of which.
		// Both are per notification, in seconds, and overridable per app under
		// Users/apps/android/<app>/connectTimeout and .../timeout. (ro#729)
		$connectTimeout = Q_Config::get('Users', 'apps', 'android', Q::app(), 'connectTimeout', 5);
		$timeout = Q_Config::get('Users', 'apps', 'android', Q::app(), 'timeout', 10);
		foreach (self::$push as $notification) {
			$fields = array(
				'to' => self::$device->deviceId,
				'notification' => $notification
			);
			$headers = array(
				'Authorization: key=' . $apiKey,
				'Content-Type: application/json'
			);
			$ch = curl_init();
			curl_setopt($ch, CURLOPT_URL, 'https://fcm.googleapis.com/fcm/send');
			curl_setopt($ch, CURLOPT_POST, true);
			curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
			curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
			// Verify the peer and its hostname: this request carries the
			// server key, which must never go out over unverified TLS. (ro#812)
			curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
			curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);
			curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($fields));
			curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, $connectTimeout);
			curl_setopt($ch, CURLOPT_TIMEOUT, $timeout);
			$result = curl_exec($ch);
			curl_close($ch);
		}
		self::$push = [];
	}

	static protected $push = [];

	static $device = null;

}