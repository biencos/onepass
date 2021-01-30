let tableBody, decryptBody, addPasswordForm, addPasswordButton, masterPasswordForm, masterPasswordButton;

const MASTER_PASSWORD_MIN_LENGTH = 8
const MASTER_PASSWORD_MAX_LENGTH = 30
const SERVICE_NAME_MIN_LENGTH = 1
const SERVICE_NAME_MAX_LENGTH = 30

window.onload = function() {
    initialize();
}

function initialize() {
    tableBody = document.getElementById("table-body");
    decryptBody = document.getElementById("decrypt-body");

    addPasswordForm = document.getElementById("add_frm");
    addPasswordButton = document.getElementById("add-password-button");

    newName = document.getElementById("new-name");
    newPassword = document.getElementById("new-password");
    masterPass = document.getElementById("master-pass");

    masterPasswordForm = document.getElementById("master_frm");
    masterPasswordButton = document.getElementById("master-password-button");

    serviceName = document.getElementById("master-name");
    masterPassword = document.getElementById("master-password");

    addPasswordButton.onclick = () => {
        addPasswordButton.hidden = true;
        addPassword();
        addPasswordButton.hidden = false;
    }
    masterPasswordButton.onclick = () => {
        masterPasswordButton.hidden = true;
        verifyMasterPassword();
        masterPasswordButton.hidden = false;
    }
    getPasswords();
}

function validateAddForm() {
    if (("" + newName.value).length < SERVICE_NAME_MIN_LENGTH) {
        alert("Nazwa serwisu jest zbyt krótka!");
        return false;
    }
    if (("" + newName.value).length > SERVICE_NAME_MAX_LENGTH) {
        alert("Nazwa serwisu jest zbyt długa!");
        return false;
    }
    if (("" + newPassword.value).length <= 0) {
        alert("Hasło nie może być puste!");
        return false;
    }
    if (("" + newPassword.value).length > 40) {
        alert("Hasło nie powinno być aż tak długie!");
        return false;
    }
    if (("" + masterPass.value).length < MASTER_PASSWORD_MIN_LENGTH) {
        alert("Hasło główne jest zbyt krótkie!");
        return false;
    }
    if (("" + masterPass.value).length > MASTER_PASSWORD_MAX_LENGTH) {
        alert("Hasło główne nie powinno być aż tak długie!");
        return false;
    }
    return true
}

function validateVerifyForm() {
    if (("" + serviceName.value).length < SERVICE_NAME_MIN_LENGTH) {
        alert("Nazwa serwisu jest zbyt krótka!");
        return false;
    }
    if (("" + serviceName.value).length > SERVICE_NAME_MAX_LENGTH) {
        alert("Nazwa serwisu jest zbyt długa!");
        return false;
    }
    if (("" + masterPassword.value).length < MASTER_PASSWORD_MIN_LENGTH) {
        alert("Hasło główne jest zbyt krótkie!");
        return false;
    }
    if (("" + masterPassword.value).length > MASTER_PASSWORD_MAX_LENGTH) {
        alert("Hasło główne nie powinno być aż tak długie!");
        return false;
    }
    return true
}

function addPassword() {
    if (validateAddForm()) {
        let formData = new FormData(addPasswordForm);
        fetch("/passes", { method: 'POST', body: formData }).then(res => {
            if (res.status === 201) {
                addPasswordForm.reset();
                getPasswords();
                alert("Hasło zostało dodane!");
            } else {
                if (res.status === 429) {
                    alert("Podczas dodawania hasła wystąpił błąd. Spróbuj ponownie za kilka minut!");
                } else {
                    alert("Podczas dodawania hasła wystąpił błąd. Spróbuj ponownie później!");
                }
            }
        });
    }
}

function verifyMasterPassword() {
    ut = document.getElementById("unciphered-text")
    if (validateVerifyForm()) {
        let formData = new FormData(masterPasswordForm);
        fetch("/passes/master", { method: 'POST', body: formData }).then(res => {
            if (res.status === 200) {
                res.json().then(obj => {
                    ut.innerHTML = 'Twoje hasło do serwisu ' + serviceName.value + ' to:   ' + obj['pass'];
                    //alert('Dla serwisu ' + serviceName + ' twoje hasło to:\n' + obj['pass'])
                    masterPasswordForm.reset();
                    alert("Hasło dla serwisu " + serviceName.value + " zostało odszyfrowane!");
                });
            } else {
                ut.innerHTML = ""
                if (res.status === 429) {
                    alert("Podczas odszyfrowywania hasła wystąpił błąd. Spróbuj ponownie za kilka minut!");
                } else {
                    alert("Podczas odszyfrowywania hasła wystąpił błąd. Spróbuj ponownie później!");
                }
            }
        });
    } else {
        ut.innerHTML = "";
    }
}


function getPasswords() {
    fetch("/passes").then(res => { res.json().then(obj => fillPasswordsTable(obj['passes'])); })
}


function fillPasswordsTable(passes) {
    while (tableBody.children.length > 0)
        tableBody.deleteRow(0);

    passes.forEach(
        pass => {
            const row = tableBody.insertRow(-1);
            for (k in pass) {
                var td = document.createElement('td');
                var cv = document.createTextNode(pass[k]);
                td.appendChild(cv);
                row.appendChild(td);
            }
        });
}