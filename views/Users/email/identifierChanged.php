<?php
	$what = array(
		'replaced' => "was just replaced",
		'added' => "was just added to your account",
		'removed' => "was just removed from your account"
	);
	$verb = isset($what[$kind]) ? $what[$kind] : $what['replaced'];
?>
<h1>
	Your sign-in <?php echo $type ?> was <?php echo $kind === 'added' ? 'added' : ($kind === 'removed' ? 'removed' : 'changed') ?> on <?php echo $communityName ?>
</h1>

<p>
	Hi <?php echo $user->username ?>, a <?php echo $type ?> you can sign in with
	<?php echo $verb ?><?php if ($invalidated): ?>, and your other signed-in devices were signed out<?php endif ?>.
</p>

<p>
	If that was you, there is nothing to do. If it wasn't, someone else has
	access to your account: reply to this email or contact the community
	organizers right away.
</p>
