/*
The MIT License (MIT)

Copyright (c) 2013 Casey Rojas

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

function EasyCrypto() {
    var self = this;
    
    this.Init = function() {
        self.crypto       = window.crypto || window.msCrypto;
        self.keysize      = 2048;
        self.pubexp       = new Uint8Array([1,0,1]);
        self.sign_algo    = 'RSASSA-PKCS1-v1_5';
        self.encrypt_algo = 'RSAES-PKCS1-v1_5';
        self.hash         = 'SHA-256'; 
        self.pubkey       = null;
        self.privkey      = null;
        
        var key = window.localStorage.getItem('public');
        if(key) {
            self.ImportKey(key)
        }
        
        key = window.localStorage.getItem('private');
        if(key) {
            self.ImportKey(key);
        }
    };
    
    this.GenerateKey = function(options) {
        options = self._GetGenParams(options);
    
        var genkey = self.crypto.subtle.generateKey(options, true, ['sign', 'verify']);
        
        genkey.onerror = self.GenerateKeyError;
        genkey.oncomplete = self.GenerateKeyComplete;
    };
    
    this.GenerateKeyError = function(event) {
        alert("Failed to generateKey");
    }
    
    this.GenerateKeyComplete = function(event) {
        self.pubkey = event.target.result.publicKey;
        self.privkey = event.target.result.privateKey;

        self.ExportKey(self.pubkey);
        self.ExportKey(self.privkey);
    };
    
    this.ExportKey = function(key) {
        var exporter = self.crypto.subtle.exportKey('jwk', key)
        
        exporter.onerror    = function(event) { return self.ExportKeyError(event, key.type); }
        exporter.oncomplete = function(event) { return self.ExportKeyComplete(event, key.type); }
    };
    
    this.ExportKeyError = function(event, type) {
        alert("Failed to export " + type + " key");
    };
    
    this.ExportKeyComplete = function(event, type) {
        window.localStorage.setItem(type, self._ArrayBufferToString(event.target.result));
    };
    
    this.ImportKey = function(key) {
        if(!(key instanceof ArrayBuffer)) {
            key = self._StringToArrayBuffer(key);
        }

        var signer = self.crypto.subtle.importKey('jwk', key, self.sign_algo);
        
        signer.onerror = self.ImportKeyError;
        signer.oncomplete = self.ImportKeyComplete;
    };
    
    this.ImportKeyError = function(event) {
        alert('ImportKey failed');
    };
    
    this.ImportKeyComplete = function(event) {
        var key = event.target.result;
        
        if(key.type === 'public') {
            self.pubkey = key;
        }
        else if(key.type === 'private') {
            self.privkey = key;
        }
        else {
            alert('ImportKey failed even though it looks like it completed');
        }
    };
    

    this.Sign = function(data, options) {
        options = self._GetSignParams(options);

        if(!(data instanceof ArrayBuffer)) {
            data = self._StringToArrayBuffer(data);
        }

        var signer = self.crypto.subtle.sign(options, self.privkey, data);

        signer.onerror = self.SignError;
        signer.oncomplete = self.SignComplete;  
    };

    this.SignError = function(event) {
        alert('Signature failed.')
    };

    this.SignComplete = function(event) {
        var signature = event.target.result;

        alert(self._ArrayBufferToBase64String(signature));
    };


    this.Verify = function(sig, data, key, options) {
        key     = key || self.pubkey;
        options = self._GetSignParams(options);

        if(!(sig instanceof ArrayBuffer)) {
            sig = self._String64ToArrayBuffer(sig);
        }  

        if(!(data instanceof ArrayBuffer)) {
            data = self._StringToArrayBuffer(data);
        }       

        var verifier = self.crypto.subtle.verify(options, key, sig.buffer, data);

        verifier.onerror = self.VerifyError;
        verifier.oncomplete = self.VerifyComplete;
    };

    this.VerifyError = function(event) {
        alert('Verify failed.')
    };

    this.VerifyComplete = function(event) {
        if(event.target.result) {
            alert("The signature was valid.");
        }
        else {
            alert("The signature was not valid.");
        }
    };

    this.Encrypt = function(data, key, options) {
        key     = key || self.pubkey;
        options = options || {name: self.encrypt_algo};

        if(!(data instanceof ArrayBuffer)) {
            data = self._StringToArrayBuffer(data);
        }

        var encrypter = self.crypto.subtle.encrypt(options, key, data);

        encrypter.onerror = self.EncryptError;
        encrypter.oncomplete = self.EncryptComplete;
    };


    this.EncryptError = function(event) {
        alert("Encryption failed.")
    };


    this.EncryptComplete = function(event) {
        var cypher = event.target.result;
        var b64_cypher = self._ArrayBufferToBase64String(cypher);

        alert(b64_cypher);
    };

    this.Decrypt = function(data, key, options) {
        key     = key     || self.privkey;
        options = options || {name: self.encrypt_algo};

        if(!(data instanceof ArrayBuffer)) {
            data = self._String64ToArrayBuffer(data);
        }

        var decrypter = self.crypto.subtle.decrypt(options, key, data);

        decrypter.onerror = self.DecryptError;
        decrypter.oncomplete = self.DecryptComplete;
    };

    this.DecryptError = function(event) {
        alert("Decryption failed.")
    };

    this.DecryptComplete = function(event) {
        var plaintext_ab = event.target.result;
        var endindex     = Array.apply(null, new Uint8Array(plaintext_ab)).indexOf(0);
        var plaintext    = self._ArrayBufferToString(plaintext_ab).substr(0, endindex);

        alert(plaintext);   
    }

    this._ArrayBufferToString = function(buffer) {
        var binary = ''
        var bytes  = new Uint8Array( buffer )
        var len    = bytes.byteLength;
        
        for (var i = 0; i < len; i++) {
            binary += String.fromCharCode( bytes[i] )
        }
        
        return binary;
    };
    
    this._ArrayBufferToBase64String = function(buffer) {
        return window.btoa( self._ArrayBufferToString(buffer) );
    };

    this._StringToArrayBuffer = function(str) {
        var bufView = new Uint8Array(str.length);
        
        for (var i = 0, strLen = str.length; i < strLen; i++) {
            bufView[i] = str.charCodeAt(i);
        }
        
        return bufView;
    };
    
    this._String64ToArrayBuffer = function(str) {
        return self._StringToArrayBuffer(atob(str));
    };
        
    this._GetGenParams = function(params) {
        if(params == undefined) {
            params = {name    : self.sign_algo, 
                      keysize : self.keysize,
                      pubexp  : self.pubexp};
        }
        else {
            params.name    = params.name    || self.sign_algo;
            params.keysize = params.keysize || self.keysize;
            params.pubexp  = params.pubexp  || self.pubexp;
        }    
    
        return { name           : params.name, 
                 modulusLength  : params.keysize,
                 publicExponent : params.pubexp };
    };

    this._GetSignParams = function(params) {
        if(params == undefined) {
            params = {name    : self.sign_algo, 
                      hash    : self.hash};
        }
        else {
            params.name = params.name || self.sign_algo;
            params.hash = params.hash || self.hash;
        }    
    
        return { name : params.name, 
                 hash : params.hash};
    };
    
    self.Init();
}