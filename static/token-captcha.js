(function () {
    var section = document.getElementById('captcha-section');
    var widget = document.getElementById('captcha-widget');
    var field = document.getElementById('captcha-token');
    var note = document.getElementById('captcha-note');
    var submit = document.getElementById('submit-btn');
    var widgetId = null;
    var timer = null;
    var ownershipVerified = false;
    var generation = 0;
    var lockedMessage = 'Verify token ownership to enable CAPTCHA verification.';

    function updateSubmit() {
        submit.disabled = !ownershipVerified || !field.value;
    }
    function clear(message) {
        field.value = '';
        clearTimeout(timer);
        note.textContent = ownershipVerified ? message : lockedMessage;
        updateSubmit();
    }
    function reset() {
        clear('Please complete a new CAPTCHA, then submit within 1 minute.');
        if (ownershipVerified && widgetId !== null && window.turnstile) window.turnstile.reset(widgetId);
    }
    window.tokenCaptchaFailed = function () {
        clear('CAPTCHA could not load or verify. Check your connection and refresh the page.');
    };
    window.initTokenCaptcha = function () {
        if (!ownershipVerified || widgetId !== null) return;
        if (!widget.dataset.sitekey) {
            clear('CAPTCHA is not configured. Please contact support.');
            return;
        }
        if (!window.turnstile) return;
        var currentGeneration = generation;
        widgetId = window.turnstile.render(widget, {
            sitekey: widget.dataset.sitekey,
            action: 'token_submission',
            theme: 'dark',
            size: 'flexible',
            'response-field': false,
            callback: function (token) {
                if (!ownershipVerified || currentGeneration !== generation) return;
                clear('Verified. Click Submit for Review within 1 minute.');
                field.value = token;
                updateSubmit();
                timer = setTimeout(reset, 60000);
            },
            'expired-callback': function () { if (currentGeneration === generation) reset(); },
            'timeout-callback': function () { if (currentGeneration === generation) reset(); },
            'error-callback': function () {
                if (currentGeneration === generation) window.tokenCaptchaFailed();
            }
        });
    };
    window.setTokenCaptchaOwnership = function (verified) {
        ownershipVerified = verified;
        section.disabled = !verified;
        section.setAttribute('aria-disabled', String(!verified));
        widget.hidden = !verified;
        widget.inert = !verified;
        if (!verified) {
            generation++;
            clear(lockedMessage);
            if (widgetId !== null && window.turnstile) window.turnstile.remove(widgetId);
            widgetId = null;
        } else {
            clear('Loading CAPTCHA…');
            window.initTokenCaptcha();
        }
    };
    window.tokenCaptchaReady = function () {
        if (ownershipVerified && field.value) return true;
        clear(widget.dataset.sitekey
            ? 'Please complete the CAPTCHA before submitting.'
            : 'CAPTCHA is not configured. Please contact support.');
        section.scrollIntoView({ behavior: 'smooth', block: 'center' });
        return false;
    };
    window.addEventListener('pageshow', function (event) {
        if (event.persisted) reset();
    });
    window.setTokenCaptchaOwnership(false);
})();
