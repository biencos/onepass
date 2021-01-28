const PASSWORD_MIN_LENGTH = 8
const PASSWORD_MAX_LENGTH = 30

window.onload = function() {
    initialize();
}

function initialize() {
    var password = document.getElementById("password");
    password.addEventListener("keyup", function() {
        var strengthbar = document.getElementById("password-meter");
        checkpassword(password.value, strengthbar);
    });

    var master_password = document.getElementById("master_password");
    master_password.addEventListener("keyup", function() {
        var strengthbar = document.getElementById("master-password-meter");
        checkpassword(master_password.value, strengthbar);
    });
}

function checkpassword(password, strengthbar) {
    var strength = 0;
    if (password.length >= PASSWORD_MIN_LENGTH && password.length <= PASSWORD_MAX_LENGTH) {
        strength += 1;
    }
    if (password.match(/[a-z]+/)) {
        strength += 1;
    }
    if (password.match(/[A-Z]+/)) {
        strength += 1;
    }
    if (password.match(/[0-9]+/)) {
        strength += 1;
    }
    if (password.match(/[$@#&!]+/)) {
        strength += 1;
    }

    switch (strength) {
        case 0:
            strengthbar.value = 0;
            break;

        case 1:
            strengthbar.value = 20;
            break;

        case 2:
            strengthbar.value = 40;
            break;

        case 3:
            strengthbar.value = 60;
            break;

        case 4:
            strengthbar.value = 80;
            break;

        case 5:
            strengthbar.value = 100;
            break;
    }
}