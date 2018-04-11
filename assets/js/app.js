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
    var pubKeyString = null;
    var privKeyObj = null;
    var symmKeyObj = null;
    var symmKeyString = null;










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
        privKeyObj = cryptico.generateRSAKey(passwordInput.value, 1024);

        // Convert private key object to string
        //TODO: CHECK: privKeyString returns no string in console.log!
        // let privKeyString = cryptico.bytes2string(privKeyObj);
        // console.log("Private key (stringified) is: " + privKeyString);

        let privKeyString = JSON.stringify(privKeyObj);
        console.log("Private key (JSON) is: " + privKeyString);

        // Generate public key (returns a string)
        pubKeyString = cryptico.publicKeyString(privKeyObj);
        console.log("Public key is: " + pubKeyString);


        //*** STORE KEYS IN THE DATABASE (JSON) LINKED TO THE LOGGED USER *** //

        // Call function to write userID + keys to database
        let user = defaultAuthentication.currentUser;
        writeKeyData(user.email, privKeyString, pubKeyString);
    });





    // Create a json entry as a child of branch "keys" with unique identifier "push()"
    // and stores it in the Firebase Database
    function writeKeyData(email, privateK, publicK) {
        let postData = {
            email: email,
            privateKey: privateK,
            publicKey: publicK
        };
        defaultDatabase.ref().child('keys').push().set(postData);
        console.log("Saved" + postData); //TODO: postdata shows nothing in log?
    }

    ////////// **********  PRIVATE & PUBLIC KEYS **********//////////










    ////////// **********  SYMMETRIC KEY & ENCRYPTION **********//////////

    // Listen for file selection
    selectFileButton.addEventListener('change', function(e) {




        //*** GENERATE SYMMETRIC KEY***//

        // Generate random symmetric key
        symmKeyObj = cryptico.generateAESKey();
        console.log("Symmetric key is: " + symmKeyObj);

        // Convert symmetric key object to a string
        symmKeyString = cryptico.bytes2string(symmKeyObj);
        console.log("Symmetric key (stringified) is: " + symmKeyString);


        //*** GET/ READ FILE***//

        // Get file
        var file = e.target.files[0];

        // The HTML5 FileReader object allows to read the contents of the selected file
        var reader = new FileReader();

        // After the reader finished reading the file do the following:
        reader.onload = function (e) {
            defaultDatabase.ref('keys').once('value', function(snapshot) {

                snapshot.forEach(function(childSnapshot) {

                    var key = childSnapshot.val();
                    var keyId = childSnapshot.key;
                    console.log(keyId + ' - ' + key.email + ' - '+ key.publicKey);

                    if(key.email === recipientEmail.value) {
                        pubKeyString = key.publicKey;
                    }

                });
            });

            //*** ENCRYPTION AND HASHING ***//

            // Encrypt file content with symmetric key => File'
            var plaintext = e.target.result;
            var fileEncrypted = cryptico.encryptAESCBC(plaintext, symmKeyObj);
            console.log("File encrypted: " + fileEncrypted);

            // TODO retrieve puboic key from recipient

            // Encrypt the symmetric key => Symm'
            var pubKeyObj = cryptico.publicKeyFromString(pubKeyString);
            var symmKeyEncrypted = cryptico.b16to64(pubKeyObj.encrypt(symmKeyString));
            console.log("SymKey encrypted: " + symmKeyEncrypted);

            // Hash the original file => FileHash
            var fileHashed = SHA256(plaintext);
            console.log("File hashed: " + fileHashed);



            //*** CALL FUNCTION TO STORE RESULTS IN THE DATABASE & STORAGE***//
            upload(file.name, fileEncrypted, symmKeyEncrypted, fileHashed);
        };

        // This will encode the contents of the file into a data-uri.
        // It will trigger the onload handler above, with the result
        reader.readAsDataURL(file);
    });


    //*** STORE ENCRYPTED FILE IN STORAGE AND THE REST IN THE DATABASE ***//
    function upload(fileName, fileEnc, symmKeyEnc, fileHash) {

        // Create a storage reference for files=> defaultStorage.ref('folder_name/file_name');
        // fileName is a pointer (reference) to where the actual file will be saved
        var storageRef = defaultStorage.ref('transfer_files/' + fileName);

        // Upload the file, and if it is successful then add the symmKeyEnc and file Hash to Database
        storageRef.putString(fileEnc)
            .then(function(snapshot) {
                console.log('complete');
                var user = defaultAuthentication.currentUser;
                writeFileData(user.uid, fileName, symmKeyEnc, fileHash);
            });
    }





    // Create a json entry as a child of branch "files" with unique identifier "push()"
    // and stores it in the Firebase Database
    function writeFileData(userId, fileName, symmKeyEnc, fileHash) {
        var postData = {
                userId: userId,
                fileName: fileName,
                symmetricKey: symmKeyEnc,
                fileHash: fileHash
        };
        defaultDatabase.ref().child('files').push().set(postData);
        console.log("Saved" + postData); //TODO: postdata shows nothing in log?
    }

    ////////// **********  SYMMETRIC KEY & ENCRYPTION **********//////////









    ////////// **********  DECRYPTION **********//////////


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

        var symmetricKeyString = privKeyObj.decrypt(cryptico.b64to16(encryptedSymmetricKey));
        var symmetricKey = cryptico.string2bytes(symmetricKeyString);

        console.log(symmetricKeyString);

        var fileDecrypted = cryptico.decryptAESCBC(text, symmetricKey);

        console.log(fileDecrypted);
    }

    ////////// **********  DECRYPTION **********//////////

})();


