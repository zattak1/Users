<?php
	$verb = $kind === 'added' ? 'added to' : ($kind === 'removed' ? 'removed from' : 'changed on');
?>
<?php echo $communityName ?>: a sign-in <?php echo $type ?> was <?php echo $verb ?> your account<?php if ($invalidated): ?> and your other devices were signed out<?php endif ?>. If this wasn't you, contact the community organizers now.
