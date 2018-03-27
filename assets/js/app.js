(function() {

    ////////// *** INITIALIZE FIREBASE ***//////////
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
    var defaultAuthentication = firebase.auth();
    var defaultStorage = firebase.storage();
    var defaultDatabase = firebase.database();
    ////////// *** INITIALIZE FIREBASE ***//////////



    // Get all DOM-elements from html
    const txtEmail = document.getElementById('txtEmail');
    const txtPassword = document.getElementById('txtPassword');
    const btnLogin = document.getElementById('btnLogin');
    const btnSignUp = document.getElementById('btnSignUp');
    const btnLogout = document.getElementById('btnLogout');

    // Get DOM-elements for storage and database
    var uploader = document.getElementById('uploader');
    var uploadFileButton = document.getElementById('uploadFileButton');
    var listDownloads = document.getElementById('listDownloads');
    var uploadKeys = document.getElementById('uploadKeys');

    // Declare global variables
    var publicKey = null;
    var symmetricKey = null;
    var symmetricKeyString = null;



    //*** AUTHENTICATION ***//

    // Add signup event
    btnSignUp.addEventListener('click', e => {

        // Get email and password
        //TODO: check for real emails
        const email = txtEmail.value;
        const pass = txtPassword.value;

    	// Create user with email and password
    	const promise = defaultAuthentication.createUserWithEmailAndPassword(email,pass);
    	promise.catch(e =>
            console.log(e.message));
    });

    // Add login event
    btnLogin.addEventListener('click', e => {

        // Get email and password
        //TODO: check for real emails
        const email = txtEmail.value;
        const pass = txtPassword.value;

        // Sign in
        const promise = defaultAuthentication.signInWithEmailAndPassword(email,pass);
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



    //*** GENERATE PRIVATE AND PUBLIC KEYS AND STORE THEM IN THE DATABASE *** //

    //TODO: If user already exists, do not generate/ add keys

    // Add uploadKeys event
    uploadKeys.addEventListener('click', function () {

        // Generate private key (returns an RSA object)
        var privateKey = cryptico.generateRSAKey('RSAKey text', 1024);
        console.log("Private key is: " + privateKey);

        // Convert private key object to string
        //TODO: CHECK: privateKeyString returns no string in console.log!
        var privateKeyString = cryptico.bytes2string(privateKey);
        console.log("Private key (stringified) is: " + privateKeyString);

        // Generate public key (returns a string)
        publicKey = cryptico.publicKeyString(privateKey);
        console.log("Public key is: " + publicKey);

        // Write keys + userID to database
        var user = defaultAuthentication.currentUser;
        writeKeyData(user.uid, privateKeyString, publicKey);
    });

    // Create a json entry as a child of branch "keys" with unique identifier (push() )
    function writeKeyData(userId, privateK, publicK) {
        var postData = {
            userId: userId,
            privateKey: privateK,
            publicKey: publicK
        };
        defaultDatabase.ref().child('keys').push().set(postData);
        console.log("Saved" + postData);
    }



    //*** GENERATE SYMMETRIC KEY AND STORE IN DATABASE. ENCRYPT FILE AND UPLOAD TO "FIREBASE STORAGE" ***//

    // Listen for file upload selection
    uploadFileButton.addEventListener('change', function(e) {

        // Generate symmetric key
        symmetricKey = cryptico.generateAESKey();
        console.log("Symmetric key is: " + symmetricKey);

        // Convert symmetric key object to a string
        symmetricKeyString = cryptico.bytes2string(symmetricKey);
        console.log("Symmetric key (stringified) is: " + symmetricKeyString);

        // Get file
        var file = e.target.files[0];

        // The HTML5 FileReader object allows to read the contents of the selected file
        var reader = new FileReader();

        // After the reader finished reading the file do the following:
        reader.onload = function (e) {

            // Encrypt file with symmetric key
            var plaintext = e.target.result;
            var fileEncrypted = cryptico.encryptAESCBC(plaintext, symmetricKey);

            //TODO: MAKE HASH (SHA-256?) FROM FILE AND STORE IT

            // Upload name of file, file encrypted and symmetric ley encrypted to FIREBASE STORAGE
            upload(file.name, fileEncrypted, symmetricKeyString);
        };

        // This will encode the contents of the file into a data-uri.
        // It will trigger the onload handler above, with the result
        reader.readAsDataURL(file);
    });

    function upload(fileName, fileEncrypted, symmetricKeyString) {

        // Encrypt the symetric key
        var pKey = cryptico.publicKeyFromString(publicKey);
        var encryptedSymmetricKey = cryptico.b16to64(pKey.encrypt(symmetricKeyString));

        // Create a storage reference for files=> defaultStorage.ref('folder_name/file_name');
        // fileName is a pointer (reference) to where the actual file will be saved
        var storageRef = defaultStorage.ref('transfer_files/' + fileName);

        // Upload the file, and if it is successful then add the  encryptedSymmetricKey
        var uploadTask = storageRef.putString(fileEncrypted);

        // Update progress bar
        uploadTask.on('state_changed',

            function progress(snapshot) { //state changes are represented by snapshots
                uploader.value = (snapshot.bytesTransferred / snapshot.totalBytes) * 100;
            }
            ,function error(err) {
                console.log('error');
                console.log(err);
            },
            function complete() {
                console.log('complete');
                var user = defaultAuthentication.currentUser;
                writeFileData(user.uid, fileName, encryptedSymmetricKey);
            }
        );
    }

    //*** READ METADATA FROM "FIREBASE DATABASE"  ***//

    //Create a json entry as a child of branch "files" with unique identifier (push() )
    function writeFileData(userId, fileName, symmetricKeyString) {
        var postData = {
                userId: userId,
                fileName: fileName,
                symmetricKey: symmetricKeyString
        };
        defaultDatabase.ref().child('files').push().set(postData);
        console.log("Saved" + postData);
    }


    //*** DOWNLOAD DATA TO CONSOLE ***//

    // Listen for file download selection and show result in the console (all files) as "fileID - fileName - userID"
    listDownloads.addEventListener('click', function(e) {

        defaultDatabase.ref('files').once('value', function(snapshot) {

            snapshot.forEach(function(childSnapshot) {

                var file = childSnapshot.val();
                var fileID = childSnapshot.key;
                console.log(fileID + ' - ' + file.fileName + ' - '+ file.userId);

                var storageRef = defaultStorage.ref('transfer_files/' + file.fileName);

                storageRef.getDownloadURL().then(function(url){

                    console.log(url);
                })
            });
        });
    })
})();


