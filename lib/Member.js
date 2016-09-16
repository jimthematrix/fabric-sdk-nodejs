var api = require('./api.js');
var util = require('util');
var stats = require('./stats.js');

var Member = api.Member.extend({

    _chain: null, //Chain
    _name: "",
    _roles: null, //string[]
    _account: "",
    _affiliation: "",
    _enrollmentSecret: "",
    _enrollment: null,
    _memberServices: null, //MemberServices
    _keyValStore: null,
    _keyValStoreName: "",
    _tcertGetterMap: {}, //{[s:string]:TCertGetter}
    _tcertBatchSize: -1,

    /**
     * Constructor for a member.
     * @param cfg {string | RegistrationRequest} The member name or registration request.
     * @returns {Member} A member who is neither registered nor enrolled.
     */
    constructor: function(cfg, chain) {
        if (util.isString(cfg)) {
            this._name = cfg;
        } else if (util.isObject(cfg)) {
            var req = cfg;
            this._name = req.enrollmentID || req.name;
            this._roles = req.roles || ['fabric.user'];
            this._account = req.account;
            this._affiliation = req.affiliation;
        }
        this._chain = chain;
        this._memberServices = chain.getMemberServices();
        this._keyValStore = chain.getKeyValueStore();
        this._keyValStoreName = toKeyValueStoreName(this._name);
        this._tcertBatchSize = chain.getTCertBatchSize();
    },

    /**
     * Get the member name.
     * @returns {string} The member name.
     */
    getName: function() {
        return this._name;
    },

    /**
     * Get the chain.
     * @returns {Chain} The chain.
     */
    getChain: function() {
        return this._chain;
    },

    /**
     * Get the member services.
     * @returns {MemberServices} The member services.
     */
    getMemberServices: function() {
        return this._memberServices;
    },

    /**
     * Get the roles.
     * @returns {string[]} The roles.
     */
    getRoles: function() {
        return this._roles;
    },

    /**
     * Set the roles.
     * @param roles {string[]} The roles.
     */
    setRoles: function(roles) {
        this._roles = roles;
    },

    /**
     * Get the account.
     * @returns {string} The account.
     */
    getAccount: function() {
        return this._account;
    },

    /**
     * Set the account.
     * @param account The account.
     */
    setAccount: function(account) {
        this._account = account;
    },

    /**
     * Get the affiliation.
     * @returns {string} The affiliation.
     */
    getAffiliation: function() {
        return this._affiliation;
    },

    /**
     * Set the affiliation.
     * @param affiliation The affiliation.
     */
    setAffiliation: function(affiliation) {
        this._affiliation = affiliation;
    },

    /**
     * Get the transaction certificate (tcert) batch size, which is the number of tcerts retrieved
     * from member services each time (i.e. in a single batch).
     * @returns The tcert batch size.
     */
    getTCertBatchSize: function() {
        if (this._tcertBatchSize === undefined) {
            return this._chain.getTCertBatchSize();
        } else {
            return this._tcertBatchSize;
        }
    },

    /**
     * Set the transaction certificate (tcert) batch size.
     * @param batchSize
     */
    setTCertBatchSize: function(batchSize) {
        this._tcertBatchSize = batchSize;
    },

    /**
     * Get the enrollment info.
     * @returns {Enrollment} The enrollment.
     */
    getEnrollment: function() {
        return this._enrollment;
    },

    /**
     * Determine if this name has been registered.
     * @returns {boolean} True if registered; otherwise, false.
     */
    isRegistered: function() {
        return this._enrollmentSecret !== "";
    },

    /**
     * Determine if this name has been enrolled.
     * @returns {boolean} True if enrolled; otherwise, false.
     */
    isEnrolled: function() {
        return this._enrollment !== null;
    },

    /**
     * Register the member.
     * @param cb Callback of the form: {function(err,enrollmentSecret)}
     */
    register: function(registrationRequest) {
        var self = this;

        return new Promise(function(resolve, reject) {
            if (registrationRequest.enrollmentID !== self.getName()) {
                reject(new Error("registration enrollment ID and member name are not equal"));
            }

            var enrollmentSecret = this._enrollmentSecret;
            if (enrollmentSecret) {
                return resolve(enrollmentSecret);
            } else {
	            self._memberServices.register(registrationRequest, self._chain.getRegistrar())
                .then(
                    function(enrollmentSecret) {

                        self._enrollmentSecret = enrollmentSecret;
                        return self.saveState();
                    }
                ).then(
                    function(data) {
                        return resolve(self._enrollmentSecret);
                    }
                ).catch(
                    function(err) {
                        reject(err);
                    }
                );
            }
        });
    },

    /**
     * Enroll the member and return the enrollment results.
     * @param enrollmentSecret The password or enrollment secret as returned by register.
     * @param cb Callback to report an error if it occurs
     */
    enroll: function(enrollmentSecret) {
        var self = this;

        return new Promise(function(resolve, reject) {
            var enrollment = self._enrollment;
            if (enrollment) {
                return resolve(enrollment);
            } else {
	            var req = {
	                enrollmentID: self.getName(),
	                enrollmentSecret: enrollmentSecret
	            };

	            self._memberServices.enroll(req)
	                .then(
	                    function(enrollment) {

	                        self._enrollment = enrollment;
	                        // Generate queryStateKey
	                        self._enrollment.queryStateKey = self._chain.cryptoPrimitives.generateNonce();

	                        // Save state
	                        return self.saveState();
	                    }
	                ).then(
	                    function(data) {
	                        // Unmarshall chain key
	                        // TODO: during restore, unmarshall enrollment.chainKey
	                        var ecdsaChainKey = self._chain.cryptoPrimitives.ecdsaPEMToPublicKey(self._enrollment.chainKey);
	                        self._enrollment.enrollChainKey = ecdsaChainKey;

	                        return resolve(enrollment);
	                    }
	                ).catch(
	                    function(err) {
	                        reject(err);
	                    }
	                );
            }
        });
    },

    /**
     * Perform both registration and enrollment.
     * @param cb Callback of the form: {function(err,{key,cert,chainKey})}
     */
    registerAndEnroll: function(registrationRequest) {
        var self = this;

        return new Promise(function(resolve, reject) {
            var enrollment = self._enrollment;
            if (enrollment) {
                return resolve(enrollment);
            } else {
	            self.register(registrationRequest)
	                .then(
	                    function(enrollmentSecret) {
	                        return self.enroll(enrollmentSecret);
	                    }
	                ).then(
	                    function(enrollment) {
	                        return resolve(enrollment);
	                    }
	                ).catch(
		                function(err) {
		                	reject(err);
		                }
		            );
            }
        });
    },

    /**
     * Issue a deploy request on behalf of this member.
     * @param deployRequest {Object}
     * @returns {TransactionContext} Emits 'submitted', 'complete', and 'error' events.
     */
    deploy: function(deployRequest) {
        var tx = this.newTransactionContext();
        tx.deploy(deployRequest);
        return tx;
    },

    /**
     * Issue a invoke request on behalf of this member.
     * @param invokeRequest {Object}
     * @returns {TransactionContext} Emits 'submitted', 'complete', and 'error' events.
     */
    invoke: function(invokeRequest) {
        var tx = this.newTransactionContext();
        tx.invoke(invokeRequest);
        return tx;
    },

    /**
     * Issue a query request on behalf of this member.
     * @param queryRequest {Object}
     * @returns {TransactionContext} Emits 'submitted', 'complete', and 'error' events.
     */
    query: function(queryRequest) {
        var tx = this.newTransactionContext();
        tx.query(queryRequest);
        return tx;
    },

    /**
     * Create a transaction context with which to issue build, deploy, invoke, or query transactions.
     * Only call this if you want to use the same tcert for multiple transactions.
     * @param {Object} tcert A transaction certificate from member services.  This is optional.
     * @returns A transaction context.
     */
    newTransactionContext: function(tcert) {
        return new TransactionContext(this, tcert);
    },

    /**
     * Get a user certificate.
     * @param attrs The names of attributes to include in the user certificate.
     * @param cb A GetTCertCallback
     */
    getUserCert: function(attrs) {
        return this.getNextTCert(attrs);
    },

    /**
     * Get the next available transaction certificate with the appropriate attributes.
     * @param cb
     */
    getNextTCert: function(attrs) {
        var self = this;

        if (!self.isEnrolled()) {
            return Promise.reject(new Error(util.format("user '%s' is not enrolled", self.getName())));
        }

        var key = getAttrsKey(attrs);

        var tcertGetter = self.tcertGetterMap[key];
        if (!tcertGetter) {
            tcertGetter = new TCertGetter(self, attrs, key);
            self.tcertGetterMap[key] = tcertGetter;
        }

        return tcertGetter.getNextTCert();
    },

    /**
     * Save the state of this member to the key value store.
     * @param cb Callback of the form: {function(err}
     */
    saveState: function() {
        return this._keyValStore.setValue(this._keyValStoreName, this.toString());
    },

    /**
     * Restore the state of this member from the key value store (if found).  If not found, do nothing.
     * @param cb Callback of the form: function(err}
     */
	restoreState() {
        var self = this;

        return new Promise(function(resolve, reject) {
        	self._keyValStore.getValue(self._keyValStoreName)
        	.then(
        		function(memberStr) {
		            if (memberStr) {
		                // The member was found in the key value store, so restore the state.
		                self.fromString(memberStr);
		            }
		            return resolve(true);
		        }
		    ).catch(
		        function(err) {
		        	reject(err);
		        }
        	);
	    });
    },

    /**
     * Get the current state of this member as a string
     * @return {string} The state of this member as a string
     */
    fromString: function(str) {
        var state = JSON.parse(str);

        if (state.name !== this.getName()) {
        	throw new Error("name mismatch: '" + state.name + "' does not equal '" + this.getName() + "'");
        }

        this._name = state.name;
        this._roles = state.roles;
        this._account = state.account;
        this._affiliation = state.affiliation;
        this._enrollmentSecret = state.enrollmentSecret;
        this._enrollment = state.enrollment;
    },

    /**
     * Save the current state of this member as a string
     * @return {string} The state of this member as a string
     */
    toString() {
        var state = {
            name: this._name,
            roles: this._roles,
            account: this._account,
            affiliation: this._affiliation,
            enrollmentSecret: this._enrollmentSecret,
            enrollment: this._enrollment
        };

        return JSON.stringify(state);
    }
});

function toKeyValueStoreName(name) {
    return "member." + name;
}

/**
 * An inner class for getting TCerts.
 * There is one class per set of attributes requested by each member.
 * @param cfg {string | RegistrationRequest} The member name or registration request.
 * @returns {Member} A member who is neither registered nor enrolled.
 */
function TCertGetter(member /*Member*/, attrs /*string[]*/, key /*string*/) {
    this.member = member;
    this.attrs = attrs;
    this.key = key;
    this.chain = member.getChain();
    this.memberServices = member.getMemberServices();
    this.tcerts = [];

    this.arrivalRate = new stats.Rate();
    this.getTCertResponseTime = new stats.ResponseTime();
    this.getTCertWaiters = [];
    this.gettingTCerts = false;
}

/**
* Get the chain.
* @returns {Chain} The chain.
*/
TCertGetter.prototype.getChain = function() {
    return this.chain;
}

TCertGetter.prototype.getUserCert = function() {
    return this.getNextTCert(cb);
}

/**
* Get the next available transaction certificate.
* @param cb
*/
TCertGetter.prototype.getNextTCert = function() {
    var self = this;
    self.arrivalRate.tick();
    var tcert = self.tcerts.length > 0? self.tcerts.shift() : undefined;

    var promise = new Promise(function(resolve, reject) {
	    if (tcert) {
	        return resolve(tcert);
	    } else {
	        self.getTCertWaiters.push({
	        	resolve: resolve,
	        	reject: reject
	        });
	    }
    });

    if (self.shouldGetTCerts()) {
        self.getTCerts();
    }

    return promise;
}

// Determine if we should issue a request to get more tcerts now.
TCertGetter.prototype.shouldGetTCerts = function() {
    // Do nothing if we are already getting more tcerts
    if (this.gettingTCerts) {
        return false;
    }
    // If there are none, then definitely get more
    if (this.tcerts.length == 0) {
        debug("shouldGetTCerts: yes, we have no tcerts");
        return true;
    }
    // If we aren't in prefetch mode, return false;
    if (!this.chain.isPreFetchMode()) {
        debug("shouldGetTCerts: no, prefetch disabled");
        return false;
    }
    // Otherwise, see if we should prefetch based on the arrival rate
    // (i.e. the rate at which tcerts are requested) and the response
    // time.
    // "arrivalRate" is in req/ms and "responseTime" in ms,
    // so "tcertCountThreshold" is number of tcerts at which we should
    // request the next batch of tcerts so we don't have to wait on the
    // transaction path.  Note that we add 1 sec to the average response
    // time to add a little buffer time so we don't have to wait.
    var arrivalRate = this.arrivalRate.getValue();
    var responseTime = this.getTCertResponseTime.getValue() + 1000;
    var tcertThreshold = arrivalRate * responseTime;
    var tcertCount = this.tcerts.length;
    var result = (tcertCount <= tcertThreshold);
    
    return result;
}

// Call member services to get more tcerts
TCertGetter.prototype.getTCerts = function() {
    var self = this;
    
    var req = {
        name: self.member.getName(),
        enrollment: self.member.getEnrollment(),
        num: self.member.getTCertBatchSize(),
        attrs: self.attrs
    };

    self.getTCertResponseTime.start();
    self.memberServices.getTCertBatch(req)
    .then(
    	function (tcerts) {
	        self.getTCertResponseTime.stop();
	        // Add to member's tcert list
	        while (tcerts.length > 0) {
	            self.tcerts.push(tcerts.shift());
	        }
	        // Allow waiters to proceed
	        while (self.getTCertWaiters.length > 0 && self.tcerts.length > 0) {
	            var waiter = self.getTCertWaiters.shift();
	            return waiter.resolve(self.tcerts.shift());
	        }
	    },
	    function(err) {
            self.getTCertResponseTime.cancel();
            // Error all waiters
            while (self.getTCertWaiters.length > 0) {
                self.getTCertWaiters.shift().reject(err);
            }
	    }
    );
}

module.exports = Member;
