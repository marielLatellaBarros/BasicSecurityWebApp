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
    const passwordInput = document.getElementById('passwordInput');
    const btnLogin = document.getElementById('btnLogin');
    const btnSignUp = document.getElementById('btnSignUp');
    const btnLogout = document.getElementById('btnLogout');

    // Get DOM-elements for storage and database
    let uploadKeys = document.getElementById('uploadKeys');
    let uploadFileButton = document.getElementById('uploadFileButton');
    let listDownloads = document.getElementById('listDownloads');

    // Declare global variables
    var publicKey = null;
    var privateKey = null;
    var symmetricKey = null;
    var symmetricKeyString = null;





    ////////// **********  AUTHENTICATION **********//////////

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
    });

    // Add signout event
    btnLogout.addEventListener('click', e => {
        defaultAuthentication.signOut();
    });

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




    ////////// **********  PRIVATE & PUBLIC KEYS **********//////////

    //TODO: If user already exists, do not generate/ add keys
    // Add uploadKeys event
    uploadKeys.addEventListener('click', function () {

        //*** GENERATE PRIVATE AND PUBLIC KEYS ***//

        // Generate private key (returns an RSA object)
        privateKey = cryptico.generateRSAKey('RSAKey text', 1024);

        // Convert private key object to string
        //TODO: CHECK: privateKeyString returns no string in console.log!
        // let privateKeyString = cryptico.bytes2string(privateKey);
        // console.log("Private key (stringified) is: " + privateKeyString);

        let privateKeyString = JSON.stringify(privateKey);
        console.log("Private key (JSON) is: " + privateKeyString);

        // Generate public key (returns a string)
        publicKey = cryptico.publicKeyString(privateKey);
        console.log("Public key is: " + publicKey);


        //*** STORE KEYS IN THE DATABASE *** //

        // Write keys + userID to database
        let user = defaultAuthentication.currentUser;
        writeKeyData(user.uid, privateKeyString, publicKey);
    });

    // Create a json entry as a child of branch "keys" with unique identifier (push() )
    function writeKeyData(userId, privateK, publicK) {
        let postData = {
            userId: userId,
            privateKey: privateK,
            publicKey: publicK
        };
        defaultDatabase.ref().child('keys').push().set(postData);
        console.log("Saved" + postData);
    }

    ////////// **********  PRIVATE & PUBLIC KEYS **********//////////




    ////////// **********  SYMMETRIC KEY & ENCRYPTION **********//////////
    //ENCRYPT FILE AND UPLOAD TO "FIREBASE STORAGE" ***//

    // Listen for file upload selection
    uploadFileButton.addEventListener('change', function(e) {

        //*** GENERATE SYMMETRIC KEY***//

        // Generate random symmetric key
        symmetricKey = cryptico.generateAESKey();
        console.log("Symmetric key is: " + symmetricKey);

        // Convert symmetric key object to a string
        symmetricKeyString = cryptico.bytes2string(symmetricKey);
        console.log("Symmetric key (stringified) is: " + symmetricKeyString);

        //this returns the same as cryptico.bytes2string()
        // var symmetricKeyString2 = JSON.stringify(symmetricKey);
        // console.log("Symmetric key (JSON) is: " + symmetricKeyString2);

        //*** GET/ READ FILE***//

        // Get file
        var file = e.target.files[0];

        // The HTML5 FileReader object allows to read the contents of the selected file
        var reader = new FileReader();

        // After the reader finished reading the file do the following:
        reader.onload = function (e) {

            //*** ENCRYPT FILE WITH SYMMETRIC KEY ***//

            // Encrypt file with symmetric key
            var plaintext = e.target.result;
            var fileEncrypted = cryptico.encryptAESCBC(plaintext, symmetricKey);

            // Encrypt the symmetric key
            var pKey = cryptico.publicKeyFromString(publicKey);
            var encryptedSymmetricKey = cryptico.b16to64(pKey.encrypt(symmetricKeyString));

            //*** HASH ORIGINAL FILE ***//
            var fileHashed = SHA256(plaintext);
            console.log("File hashed: " + fileHashed);

            //*** FILE ENCRYPTED SYMMETRIC KEY ENCRYPTED AND FILE HASHED: STORE IN THE DATABASE. ***//
            upload(file.name, fileEncrypted, encryptedSymmetricKey, fileHashed);
        };

        // This will encode the contents of the file into a data-uri.
        // It will trigger the onload handler above, with the result
        reader.readAsDataURL(file);
    });

    function upload(fileName, fileEncrypted, encryptedSymmetricKey, fileHashed) {

        // Create a storage reference for files=> defaultStorage.ref('folder_name/file_name');
        // fileName is a pointer (reference) to where the actual file will be saved
        var storageRef = defaultStorage.ref('transfer_files/' + fileName);

        // Upload the file, and if it is successful then add the  encryptedSymmetricKey
        storageRef.putString(fileEncrypted)
            .then(function(snapshot) {
                console.log('complete');
                var user = defaultAuthentication.currentUser;
                writeFileData(user.uid, fileName, encryptedSymmetricKey, fileHashed);
            });
    }

    //*** READ METADATA FROM "FIREBASE DATABASE"  ***//

    //Create a json entry as a child of branch "files" with unique identifier (push() )
    function writeFileData(userId, fileName, symmetricKeyString, fileHashed) {
        var postData = {
                userId: userId,
                fileName: fileName,
                symmetricKey: symmetricKeyString,
                fileHash: fileHashed
        };
        defaultDatabase.ref().child('files').push().set(postData);
        console.log("Saved" + postData);
    }

    ////////// **********  SYMMETRIC KEY& ENCRYPTION **********//////////


    //*** DOWNLOAD DATA TO CONSOLE ***//

    // Listen for file download selection and show result in the console (all files) as "fileID - fileName - userID"
    listDownloads.addEventListener('click', function(e) {

        defaultDatabase.ref('files').once('value', function(snapshot) {

            snapshot.forEach(function(childSnapshot) {

                var file = childSnapshot.val();
                var fileID = childSnapshot.key;
                console.log(fileID + ' - ' + file.fileName + ' - '+ file.userId + '- ' + file.fileHash + ' - ' + file.symmetricKey);

                var storageRef = defaultStorage.ref('transfer_files/' + file.fileName);

                storageRef.getDownloadURL().then(function(url){

                    console.log(url);

                    // This can be downloaded directly:
                    var xhr = new XMLHttpRequest();
                    xhr.responseType = 'text';
                    xhr.onload = function(event) {
                        var text = xhr.response;

                        console.log(text);

                        decryptFile(text, file.symmetricKey)
                    };
                    xhr.open('GET', url);
                    xhr.send();
                });

            });
        });
    })

    function decryptFile(text, encryptedSymmetricKey) {

        var symmetricKeyString = privateKey.decrypt(cryptico.b64to16(encryptedSymmetricKey));
        var symmetricKey = cryptico.string2bytes(symmetricKeyString);

        console.log(symmetricKeyString);

        var fileDecrypted = cryptico.decryptAESCBC(text, symmetricKey);

        console.log(fileDecrypted);
    }

})();


