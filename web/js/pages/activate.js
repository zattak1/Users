var Users = Q.Users;

Q.onReady.add(function() {
	$("#activate_setIdentifier").click(function() { Users.setIdentifier(); });
	$("#activate_logoutAndTryAgain").click(function () {
		Q.Users.logout({
			onSuccess: function () {
				window.location.reload(true);
			}
		}
	)})
	$("#activate_login").click(function() { Users.login(); });
	$("#new-password").val("").focus();
	
	Q.addScript("{{Q}}/js/sha1.js");
	
	var $form = $("form");
	$form.data("onBeforeSubmit", new Q.Event());
	var onBeforeSubmit = $form.data("onBeforeSubmit");
	onBeforeSubmit.set(function () {
		var $form = $(this);
		var $input = $form.find("input[name=passphrase]");
		var password = $input.val();
		$("<input type=\"hidden\" name=\"password\">").val(password).appendTo($form);
	});
	$form.on("submit", function (event) {
        if (Q.handle($form.data("onBeforeSubmit"), this) === false) {
            event.stopImmediatePropagation();
            return false;
        }
        
		var salt = Users.pages.activate.salt_json;
		if (!window.CryptoJS || !salt) {
			return;
		}
		var p = $("#new-password");
		var v = p.val();
		if (v && location.protocol !== "https:") {
			if (!/^[0-9a-f]{40}$/i.test(v)) {
				p.val(CryptoJS.SHA1(p.val() + "\t" + salt));
			}
			$("#Users_login_isHashed").attr("value", 1);
		} else {
			$("#Users_login_isHashed").attr("value", 0);
		}
	});
	
	$("#new-password").plugin("Q/placeholders").plugin("Q/clickfocus");
	
	$(".Users_activate_container .Q_buttons .Q_button").plugin("Q/clickable");
	// Upstream prepended three-word windows of Yahoo YQL review text here,
	// picked with a non-crypto RNG, as passphrase suggestions. YQL is gone and
	// public text is not a passphrase source (ro#732, Codex audit R01).
});