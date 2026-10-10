<?php
/**
 * @module Users
 */
/**
 * Class representing 'Link' rows in the 'Users' database
 * You can create an object of this class either to
 * access its non-static methods, or to actually
 * represent a link row in the Users database.
 *
 * @class Users_Link
 * @extends Base_Users_Link
 */
class Users_Link extends Base_Users_Link
{
	/**
	 * The setUp() method is called the first time
	 * an object of this class is constructed.
	 * @method setUp
	 */
	function setUp()
	{
		parent::setUp();
	}
	// No beforeSave(): upstream's assigned `secret` and `token` on insert, but
	// users_link has neither column (identifier, userId, extraInfo,
	// insertedTime), so the uniqueness SELECT on `token` failed and no row
	// could ever be inserted (ro#1077).

	/* * * */
	/**
	 * Implements the __set_state method, so it can work with
	 * with var_export and be re-imported successfully.
	 * @method __set_state
	 * @param {array} $array
	 * @return {Users_Link} Class instance
	 */
	static function __set_state(array $array) {
		$result = new Users_Link();
		foreach($array as $k => $v)
			$result->$k = $v;
		return $result;
	}
};