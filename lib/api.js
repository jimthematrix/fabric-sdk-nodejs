var Base = require('./base.js');

var UNIMPLEMENTED = function() {
	throw new Error("Unimplemented interface!");
}

var UNPROMISED = function() {
	return new Promise(function(resolve, reject) {
		reject("Unimplemented interface!");
	});
}

var KeyValStore = Base.extend({

    /**
     * Get the value associated with name.
     * @param name
     */
    getValue: function(name /*string*/) { 
    	return UNPROMISED(); 
    },

    /**
     * Set the value associated with name.
     * @param name
     * @param value
     */
    setValue(name /*string*/, value /*string*/) {
    	return UNPROMISED();
    }

});

var MemberServices = Base.extend({

    /**
     * Get the security level
     * @returns The security level
     */
    getSecurityLevel: function() {
    	UNIMPLEMENTED();
    },

    /**
     * Set the security level
     * @params securityLevel The security level
     */
    setSecurityLevel: function(securityLevel /*number*/) {
	    UNIMPLEMENTED();
    },

    /**
     * Get the hash algorithm
     * @returns The security level
     */
    getHashAlgorithm: function() {
    	UNIMPLEMENTED();
    },

    /**
     * Set the security level
     * @params securityLevel The security level
     */
    setHashAlgorithm: function(hashAlgorithm /*string*/) {
    	UNIMPLEMENTED();
    },

    /**
     * Register the member and return an enrollment secret.
     * @param req Registration request with the following fields: name, role
     * @param registrar The identity of the registar (i.e. who is performing the registration)
     * @returns promise for enrollmentSecret
     */
    register: function(req /*RegistrationRequest*/, registrar /*Member*/) {
    	return UNPROMISED();
    },

    /**
     * Enroll the member and return an opaque member object
     * @param req Enrollment request with the following fields: name, enrollmentSecret
     * @returns promise for Enrollment
     */
    enroll: function(req /*EnrollmentRequest*/) {
    	return UNPROMISED();
    },

    /**
     * Get an array of transaction certificates (tcerts).
     * @param req A GetTCertBatchRequest
     * @returns promise for TCert[]
     */
    getTCertBatch: function(req /*GetTCertBatchRequest*/) {
    	return UNPROMISED();
    }

});

module.exports.KeyValStore = KeyValStore;
module.exports.MemberServices = MemberServices;