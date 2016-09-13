var Base = require('./base.js');

module.exports.KeyValStore = Base.extend({

    /**
     * Get the value associated with name.
     * @param name
     * @returns Promise for the value
     */
    getValue: function(name /*string*/ ) {},

    /**
     * Set the value associated with name.
     * @param name
     * @param value
     * @returns Promise for a confirmed (data=true) write operation
     */
    setValue(name /*string*/ , value /*string*/ ) {}

});

module.exports.CryptoSuite = Base.extend({

    TCertEncTCertIndex: "1.2.3.4.5.6.7",

    /**
     * Get the security level
     * @returns {number} The security level
     */
    getSecurityLevel: function() {},

    /**
     * Set the security level
     * @params securityLevel The security level
     */
    setSecurityLevel: function(securityLevel /*number*/ ) {},

    /**
     * Get the hash algorithm
     * @returns {string} The hash algorithm
     */
    getHashAlgorithm: function() {},

    /**
     * Set the hash algorithm
     * @params hashAlgorithm The hash algorithm ('SHA2' or 'SHA3')
     */
    setHashAlgorithm: function(hashAlgorithm /*string*/ ) {},

    generateNonce: function() {},

    ecdsaKeyFromPrivate: function(key, encoding) {},

    ecdsaKeyFromPublic: function(key, encoding) {},

    ecdsaPrivateKeyToASN1: function(prvKeyHex /*string*/ ) {},

    ecdsaSign: function(key /*Buffer*/ , msg /*Buffer*/ ) {},

    ecdsaPEMToPublicKey: function(chainKey) {},

    eciesEncryptECDSA: function(ecdsaRecipientPublicKey, msg) {},

    ecdsaKeyGen: function() {},

    eciesKeyGen: function() {},

    eciesEncrypt: function(recipientPublicKey, msg) {},

    eciesDecrypt: function(recipientPrivateKey, cipherText) {},

    hmac: function(key, bytes) {},

    aesCBCPKCS7Decrypt: function(key, bytes) {},

    aes256GCMDecrypt(key /*Buffer*/ , ct /*Buffer*/ ) {},

    aesKeyGen: function() {},

    hmacAESTruncated: function(key, bytes) {}

});

module.exports.X509Certificate = Base.extend({

    criticalExtension: function(oid) {}

});

// Enrollment metadata
module.exports.Enrollment = Base.extend({
    key: null, /*Buffer*/
    cert: "",
    chainKey: ""
});

/**
 * A member is an entity that transacts on a chain.
 * Types of members include end users, peers, etc.
 */
module.exports.Member = Base.extend({


});

module.exports.MemberServices = Base.extend({

    /**
     * Get the security level
     * @returns The security level
     */
    getSecurityLevel: function() {},

    /**
     * Set the security level
     * @params securityLevel The security level
     */
    setSecurityLevel: function(securityLevel /*number*/ ) {},

    /**
     * Get the hash algorithm
     * @returns The security level
     */
    getHashAlgorithm: function() {},

    /**
     * Set the security level
     * @params securityLevel The security level
     */
    setHashAlgorithm: function(hashAlgorithm /*string*/ ) {},

    /**
     * Register the member and return an enrollment secret.
     * @param req Registration request with the following fields:
	 *	{
	 *
	 *	    // The enrollment ID of the member
	 *	    enrollmentID: "",
	 *
	 *	    // Roles associated with this member.
	 *	    // Fabric roles include: 'client', 'peer', 'validator', 'auditor'
	 *	    // Default value: ['client']
	 *	    roles: ["client"],
	 *
	 *	    // Affiliation for a user
	 *	    affiliation: "",
	 *
	 *	    // 'registrar' enables this identity to register other members with types
	 *	    // and can delegate the 'delegationRoles' roles
	 *	    registrar: {
	 *	        // The allowable roles which this member can register
	 *	        roles: null, //string[]
	 *
	 *	        // The allowable roles which can be registered by members registered by this member
	 *	        delegateRoles: null //string[]
	 *	    };
	 *	}
     * @param registrar The identity of the registar (i.e. who is performing the registration)
     * @returns promise for enrollmentSecret
     */
    register: function(req /*RegistrationRequest*/ , registrar /*Member*/ ) {},

    /**
     * Enroll the member and return an opaque member object
     * @param req Enrollment request with the following fields:
	 *	{
	 *
	 *	    // The enrollment ID
	 *	    enrollmentID: "",
	 *
	 *	    // The enrollment secret (a one-time password)
	 *	    enrollmentSecret: ""
	 *	}
     * @returns promise for Enrollment
     */
    enroll: function(req /*EnrollmentRequest*/ ) {},

    /**
     * Get an array of transaction certificates (tcerts).
     * @param req A GetTCertBatchRequest:
	 *	{
	 *
	 *	    name: string, 
	 * 		enrollment: an Enrollment object, 
	 * 		num: a number, 
	 *		attrs: a string[]
	 *	}
     * @returns promise for TCert[]
     */
    getTCertBatch: function(req /*GetTCertBatchRequest*/ ) {}

});

module.exports.PrivacyLevel = {
    Nominal: 0,
    Anonymous: 1
};

// The base Certificate class
module.exports.Certificate = Base.extend({

	/** 
	 * @privacyLevel: Denoting if the Certificate is anonymous or carrying its owner's identity. 
	 */
    constructor: function(cert /*Buffer*/, privateKey, privLevel /*PrivacyLevel*/) {
    	this._cert = cert;
    	this._privateKey = privateKey;
    	this._privacyLevel = privacyLevel;
    },

    encode: function() {
        return this._cert;
    }
});

/**
 * Enrollment certificate.
 */
module.exports.ECert = module.exports.Certificate.extend({

    constructor: function(cert /*Buffer*/, privateKey) {
        module.exports.Certificate.prototype.constructor(cert, privateKey, module.exports.PrivacyLevel.Nominal);
    }

});

/**
 * Transaction certificate.
 */
module.exports.TCert = module.exports.Certificate.extend({
    
    constructor: function(publicKey, privateKey) {
        module.exports.Certificate.prototype.constructor(publicKey, privateKey, module.exports.PrivacyLevel.Anonymous);
    }
});

module.exports.Chain = Base.extend({

});

module.exports.Peer = Base.extend({
    /**
     * Get the chain of which this peer is a member.
     * @returns {Chain} The chain of which this peer is a member.
     */
    getChain: function() {},

    /**
     * Get the URL of the peer.
     * @returns {string} Get the URL associated with the peer.
     */
    getUrl: function() {},

    /**
     * Send a transaction to this peer.
     * @param tx A transaction
     * @param eventEmitter The event emitter
     */
    sendTransaction: function(tx, eventEmitter) {}

});

