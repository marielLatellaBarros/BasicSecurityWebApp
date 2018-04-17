(function() {

    ////////// ********** INITIALIZE FIREBASE **********//////////
    var config = {
        apiKey: "AIzaSyDlscT61pdkcs6KCGoJRd8yOKE-QrAlMwU",
        authDomain: "basicsecuritywebapp.firebaseapp.com",
        databaseURL: "https://basicsecuritywebapp.firebaseio.com",
        projectId: "basicsecuritywebapp",
        storageBucket: "basicsecuritywebapp.appspot.com",
        messagingSenderId: "575380490967"
    };

    // Initialize app and retrieve app services
    firebase.initializeApp(config);
    let defaultAuthentication = firebase.auth();
    let defaultStorage = firebase.storage();
    let defaultDatabase = firebase.database();
    ////////// ********** INITIALIZE FIREBASE **********//////////





    // Get all DOM-elements from html
    const emailInput = document.getElementById('emailInput');
    const recipientEmail = document.getElementById('recipientEmail');
    const passwordInput = document.getElementById('passwordInput');
    const btnLogin = document.getElementById('btnLogin');
    const btnSignUp = document.getElementById('btnSignUp');
    const btnLogout = document.getElementById('btnLogout');

    // Get DOM-elements for storage and database
    let uploadKeys = document.getElementById('uploadKeys');
    let selectFileButton = document.getElementById('selectFileButton');
    let listDownloads = document.getElementById('listDownloads');

    // Declare global variables
    // TODO get rid of global vars
    var pubKeyString = null;
    var privKeyObj = null;
    var symmKeyObj = null;
    var symmKeyString = null;










    ////////// **********  AUTHENTICATION **********//////////

    btnLogout.style.visibility = "hidden";

    // Add signup event
    btnSignUp.addEventListener('click', e => {

        // Get email and password
        const email = emailInput.value; //TODO: Check email validation
        const pass = passwordInput.value; //TODO: Check password validation

    	// Create user with email and password
    	const promise = defaultAuthentication.
                        createUserWithEmailAndPassword(email,pass);
    	promise.catch(e =>
            console.log(e.message));

    	//TODO: add uploadKeys function
    	// uploadKeys();

        btnLogout.style.visibility = "visible";
        btnSignUp.style.visibility = "hidden";
        btnLogin.style.visibility = "hidden";

        console.log("User signed up");
    });

    // Add login event
    btnLogin.addEventListener('click', e => {

        // Get email and password
        const email = emailInput.value; //TODO: Check email validation
        const pass = passwordInput.value; //TODO: Check password validation

        // Sign in
        const promise = defaultAuthentication.
                        signInWithEmailAndPassword(email,pass);
        promise.catch(e =>
            console.log(e.message));

        btnLogout.style.visibility = "visible";
        btnSignUp.style.visibility = "hidden";
        btnLogin.style.visibility = "hidden";

        console.log("User signed in");
    });

    // Add signout event
    btnLogout.addEventListener('click', e => {
        defaultAuthentication.signOut();

        btnLogout.style.visibility = "hidden";
        btnSignUp.style.visibility = "visible";
        btnLogin.style.visibility = "visible";

        emailInput.value = "";
        passwordInput.value = "";
        console.log("User signed out");
    });

    //TODO: log out button via FIREBASE?
    // Add a realtime authentication listener
    defaultAuthentication.onAuthStateChanged(firebaseUser => {
    	if(firebaseUser) {
    		console.log(firebaseUser);
    		btnLogout.classList.remove('hide');
    	} else {
    		console.log('not logged in');
    		btnLogout.classList.add('hide');
    	}
    });

    ////////// **********  AUTHENTICATION **********//////////










    ////////// **********  PRIVATE & PUBLIC KEYS (RSA) **********//////////

    //TODO: replace eventListener by a function
    // Add uploadKeys event
    // function uploadKeys () {
    uploadKeys.addEventListener('click', function () {



        //*** GENERATE PRIVATE KEY***//

        // Generate private key (returns an RSA object)
        privKeyObj = generateRSAKey();
        console.log("This is the private key Object: " + privKeyObj);


        //TODO: Am I converting to a string?
        // Convert private key object (privKeyObj) components to string to store it in FIREBASE
        let N = cryptico.b16to64(privKeyObj.n.toString(16));
        let E = cryptico.b16to64(privKeyObj.e.toString(16));
        let D = cryptico.b16to64(privKeyObj.d.toString(16));

        let P = cryptico.b16to64(privKeyObj.p.toString(16));
        let Q = cryptico.b16to64(privKeyObj.q.toString(16));
        let DP = cryptico.b16to64(privKeyObj.dmp1.toString(16));
        let DQ = cryptico.b16to64(privKeyObj.dmq1.toString(16));
        let C = cryptico.b16to64(privKeyObj.coeff.toString(16));

        let privKeyData = {
            N: N,
            E: E,
            D: D,
            P: P,
            Q: Q,
            DP: DP,
            DQ: DQ,
            C: C
        };

        // This is the privKeyObj split into its different components
        console.log("Private key Data components (before JSON) is: " + privKeyData);

        // Convert the string components to a JSON format so it can be stored in FIREBASE
        let privKeyString = JSON.stringify(privKeyData);
        console.log("Private key (JSON) is: " + privKeyString);

        // Use the password of the user to generate the symmetric key (same password => same key, stored NOWHERE)
        // It returns a string, so no need to stringify
        let symmetricUserKey = generateSymmetricUserKey(passwordInput.value);
        console.log("Symmetric key for this user is: " + symmetricUserKey);

        // Use the symmetric key to encrypt the private key of the user (because it will be stored in FIREBASE)
        //TODO: Make sure you know how the AESCBC works!
        let privKeyEncrypted = cryptico.encryptAESCBC(privKeyString, symmetricUserKey);
        console.log("PRIVATE KEY ENCRYPTED is: " + privKeyEncrypted);










        //*** GENERATE PUBLIC KEY***//

        // Generate public key from private key object (returns a string)
        pubKeyString = cryptico.publicKeyString(privKeyObj);
        console.log("Public key (string) is: " + pubKeyString);










        //*** STORE KEYS IN THE DATABASE (JSON) LINKED TO THE LOGGED USER *** //

        // Call function to write userID + keys to database
        let user = defaultAuthentication.currentUser;
        writeKeyData(user.uid, user.email, privKeyEncrypted, pubKeyString);
    });









    // RSAKey() creates an empty RSA object (empty components: N, E, D, etc)
    // via the "generate" method a new random private key B (1024) bits long , using public expt E
    // Converts the string 03 to an integer and does magic!
    function generateRSAKey() {
        var rsa = new RSAKey();
        rsa.generate(1024, "03");
        return rsa;
    }




    // Because of security reasons, the user password is not stored in FIREBASE.
    // Instead it is always hashed, and generated when the user signs in or logs in
    // Because the seed is the password, then the Symmetric User key is always the same
    function generateSymmetricUserKey(password) {
        Math.seedrandom(sha256.hex(password));
        var key = new Array(32);
        var r = new SeededRandom();
        r.nextBytes(key);
        return key;
    }




    // Create a json entry as a child of branch "keys" with unique identifier "push()"
    // and stores it in the FIREBASE Database
    function writeKeyData(userId, email, privateK, publicK) {

        let postPublicData = {
            email: email,
            userId: userId,
            publicKey: publicK
        };
        defaultDatabase.ref('public_keys/' + userId).set(postPublicData);
        console.log("Saved public key data: " + postPublicData);


        let postPrivateData = {
            email: email,
            privateKey: privateK
        };
        defaultDatabase.ref('private_keys/' + userId).set(postPrivateData);
        console.log("Saved private key data: " + postPrivateData);
    }

    ////////// **********  PRIVATE & PUBLIC KEYS **********//////////







    ////////// **********  SYMMETRIC KEY (AES) & ENCRYPTION **********//////////

    // Listen for file selection
    selectFileButton.addEventListener('change', function(e) {

        //*** GENERATE SYMMETRIC KEY***//

        // Generate random symmetric key object
        symmKeyObj = cryptico.generateAESKey();
        console.log("Symmetric key is: " + symmKeyObj);

        // Convert symmetric key object to a string
        symmKeyString = cryptico.bytes2string(symmKeyObj);
        console.log("Symmetric key (stringified) is: " + symmKeyString);

        loadPublicKey(recipientEmail.value, function(publicKey, userIdPublicKey) {
            continueEncrypting(e.target.files[0], publicKey, userIdPublicKey);
        });
        // End Retrieve the public key of the recipient
    });

    function loadPublicKey(emailUser, callback) {
        // Retrieve the public key of the recipient
        defaultDatabase.ref('public_keys').once('value', function(snapshot) {

            snapshot.forEach(function(childSnapshot) {

                var value = childSnapshot.val();
                var keyId = childSnapshot.key;
                console.log(keyId + ' - ' + value.email + ' - '+ value.publicKey);

                if(value.email === emailUser) {
                    let publicKey = value.publicKey;
                    let userId = value.userId;

                    var publicKeyObj = cryptico.publicKeyFromString(publicKey);
                    callback(publicKeyObj, userId);
                }
            });
        });
    }

    function continueEncrypting(file, publicKeyRecipient, userIdRecipient) {
        //*** GET/ READ FILE***//

        // The HTML5 FileReader object allows to read the contents of the selected file
        var reader = new FileReader();

        // After the reader finished reading the file do the following:
        reader.onload = function (e) {



            //*** ENCRYPTION AND HASHING ***//

            // Encrypt file content with symmetric key => File'
            var plaintext = e.target.result;
            var fileEncrypted = cryptico.encryptAESCBC(plaintext, symmKeyObj);
            console.log("File encrypted: " + fileEncrypted);

            // Encrypt the symmetric key => Symm'
            var symmKeyEncrypted = cryptico.b16to64(publicKeyRecipient.encrypt(symmKeyString));
            console.log("SymKey encrypted: " + symmKeyEncrypted);

            // Hash the original file => FileHash
            var fileHashed = SHA256(plaintext);
            console.log("File hashed: " + fileHashed);

            let user = defaultAuthentication.currentUser;
            loadPrivateKeyUser(user.uid, function() {
                let fileHashedSigned = privKeyObj.signStringWithSHA256(fileHashed);
                console.log("Filehash signed: " + fileHashedSigned);

                //*** CALL FUNCTION TO STORE RESULTS IN THE DATABASE & STORAGE***//
                upload(userIdRecipient, user.email, file.name, fileEncrypted, symmKeyEncrypted, fileHashedSigned);
            })

        };

        // This will encode the contents of the file into a data-uri.
        // It will trigger the onload handler above, with the result
        reader.readAsDataURL(file);
    }


    //*** STORE ENCRYPTED FILE IN STORAGE AND THE REST IN THE DATABASE ***//
    function upload(userIdRecipient, emailSender, fileName, fileEnc, symmKeyEnc, fileHash) {

        // Create a storage reference for files=> defaultStorage.ref('folder_name/file_name');
        // fileName is a pointer (reference) to where the actual file will be saved
        var storageRef = defaultStorage.ref('transfer_files/' + userIdRecipient +'/' + fileName);

        // Upload the file, and if it is successful then add the symmKeyEnc and file Hash to Database
        storageRef.putString(fileEnc)
            .then(function(snapshot) {
                console.log('complete');
                writeFileData(userIdRecipient, emailSender, fileName, symmKeyEnc, fileHash);
            });
    }





    // Create a json entry as a child of branch "files" with unique identifier "push()"
    // and stores it in the Firebase Database
    function writeFileData(userIdRecipient, emailSender, fileName, symmKeyEnc, fileHash) {
        var postData = {
                userIdRecipient: userIdRecipient,
                fileName: fileName,
                symmetricKey: symmKeyEnc,
                fileHash: fileHash,
                sender: emailSender
        };
        defaultDatabase.ref().child('files/' + userIdRecipient).push().set(postData);
        console.log("Saved" + postData); //TODO: postdata shows nothing in log?
    }

    ////////// **********  SYMMETRIC KEY & ENCRYPTION **********//////////









    ////////// **********  DECRYPTION **********//////////


    //*** DOWNLOAD DATA TO CONSOLE ***//

    // Listen for file download selection and show result in the console (all files) as "fileID - fileName - userID"
    listDownloads.addEventListener('click', function(e) {

        let user = defaultAuthentication.currentUser;
        loadPrivateKeyUser(user.uid, function() {
            continueDecrypting(user.uid)
        });

    });

    function loadPrivateKeyUser(userId, callback) {

        // Make sure the private key of logged in user is known
        defaultDatabase.ref('/private_keys/' + userId).once('value').then(function(snapshot) {

            let encryptedPrivateKey = snapshot.val().privateKey;

            //The server is not allowed to see this key, otherwise the server is able to decrypt the file, which we don't want.
            let symmetricUserKey = generateSymmetricUserKey(passwordInput.value);
            console.log("Symmetric key for this user is: " + symmetricUserKey);

            var privateKeyString = cryptico.decryptAESCBC(encryptedPrivateKey, symmetricUserKey);

            let privateKeyData = JSON.parse(privateKeyString);

            var rsa = new RSAKey();
            rsa.setPrivateEx(cryptico.b64to16(privateKeyData.N),
                cryptico.b64to16(privateKeyData.E),
                cryptico.b64to16(privateKeyData.D),
                cryptico.b64to16(privateKeyData.P),
                cryptico.b64to16(privateKeyData.Q),
                cryptico.b64to16(privateKeyData.DP),
                cryptico.b64to16(privateKeyData.DQ),
                cryptico.b64to16(privateKeyData.C));

            privKeyObj = rsa;
            if(privKeyObj) {
                callback();
            }
        });
    }

    function continueDecrypting(userId) {
        defaultDatabase.ref('files/' + userId).once('value', function(snapshot) {

            snapshot.forEach(function(childSnapshot) {

                var file = childSnapshot.val();
                var fileID = childSnapshot.key;
                console.log(fileID + ' - ' + file.fileName + ' - '+ file.sender +' - '+ file.userIdRecipient + '- ' + file.fileHash + ' - ' + file.symmetricKey);

                loadPublicKey(file.sender, function(publicKeySender, userIdPublicKey) {

                    var storageRef = defaultStorage.ref('transfer_files/' + userId + '/' + file.fileName);

                    storageRef.getDownloadURL().then(function(url){

                        console.log(url);

                        // This can be downloaded directly:
                        var xhr = new XMLHttpRequest();
                        xhr.responseType = 'text';
                        xhr.onload = function(event) {
                            var text = xhr.response;

                            console.log(text);

                            fileDecrypted = decryptFile(text, file.symmetricKey);

                            // verify the Hash
                            var fileHashed = SHA256(fileDecrypted);

                            if(publicKeySender.verifyString(fileHashed, file.fileHash)) {

                                downloadFile(file.fileName, fileDecrypted);
                            } else {
                                // TODO: pretty error message
                                console.log("File hash mismatch!!!!");
                            }
                        };
                        xhr.open('GET', url);
                        xhr.send();
                    });
                });

            });
        });
    }

    function decryptFile(text, encryptedSymmetricKey) {
        var symmetricKeyString = privKeyObj.decrypt(cryptico.b64to16(encryptedSymmetricKey));
        var symmetricKey = cryptico.string2bytes(symmetricKeyString);

        console.log(symmetricKeyString);

        var fileDecrypted = cryptico.decryptAESCBC(text, symmetricKey);

        console.log(fileDecrypted);

        return fileDecrypted;
    }

    function downloadFile(filename, text) {
        var element = document.createElement('a');
        element.setAttribute('href', text);
        element.setAttribute('download', filename);

        element.style.display = 'none';
        document.body.appendChild(element);

        element.click();

        document.body.removeChild(element);
    }

    ////////// **********  DECRYPTION **********//////////

})();


