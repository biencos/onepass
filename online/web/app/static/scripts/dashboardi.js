let showInfoForm, showiName, showiMaster, showiButton,
    addInfoForm, addiName, addiUsername, addiUrl, addiImage, addiMaster, addiButton;


window.onload = function () {
    initialize();
}

function initialize() {
    // SHOW MORE INFO ABOUT ACCOUNT IN SERVICE
    showInfoForm = document.getElementById("showi_frm");
    showiName = document.getElementById("showi-name");
    showiMaster = document.getElementById("showi-master");
    showiButton = document.getElementById("showi-button");
    showiButton.onclick = () => {
        showiButton.hidden = true;
        showInfoAboutService();
        showiButton.hidden = false;
    }



    // ADD MORE INFO ABOUT PASSWORD
    addInfoForm = document.getElementById("addi_frm");
    addiName = document.getElementById("addi-name");
    addiUsername = document.getElementById("addi-username");
    addiUrl = document.getElementById("addi-url");
    addiImage = document.getElementById("addi-image");
    addiMaster = document.getElementById("addi-master");
    addiButton = document.getElementById("addi-button");
    addiButton.onclick = () => {
        addiButton.hidden = true;
        addInfoAboutService();
        addiButton.hidden = false;
    }
}


// SHOW MORE INFO ABOUT ACCOUNT IN SERVICE
function showInfoAboutService() {
    let url = "/info" + "/" + showiName.value;
    //let formData = new FormData(showInfoForm);

    fetch(url).then(res => {
        if (res.status === 200) {
            showInfoForm.reset();
            res.json().then(obj => {
                var src = obj['image_url']; //"https://www.k9thorn.pl/1242-food_thickbox_default/gogle-dla-psa-rex-spesc.jpg";
                img = document.createElement('img');
                img.src = src;
                img.style.height = '100px';
                img.style.width = '100px';
                showiImage = document.getElementById("showi-image")
                showiImage.appendChild(img);

                showiName = document.getElementById("showi-sname");
                showiName.innerHTML = 'Nazwa Serwisu: ' + obj['service_name'];

                showiUrl = document.getElementById("showi-url");
                showiUrl.innerHTML = 'URL Serwisu: ' + obj['service_url'];

                showiUsername = document.getElementById("showi-username");
                showiUsername.innerHTML = 'Twój Login (w serwisie): ' + obj['user_name'];
            });
        } else {
            alert("Podczas pobierania historii hasła wystąpił błąd. Spróbuj ponownie później!");
        }
    });
}


// ADD MORE INFO ABOUT PASSWORD
function addInfoAboutService() {
    let url = "/info";
    let method = 'POST';
    let formData = new FormData(addInfoForm);

    fetch(url, { method: method, body: formData }).then(res => {
        if (res.status === 201) {
            addInfoForm.reset();
            alert("Twój profil został dodany!");
        } else {
            alert("Podczas dodawania profilu wystąpił błąd. Spróbuj ponownie później!");
        }
    });
}


