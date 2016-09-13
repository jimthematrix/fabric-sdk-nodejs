var api = require('./api.js');
var utils = require('./utils.js');
var urlParser = require('url');
var net = require('net');
var util = require('util');
var MemberServices = require('./MemberServices.js');
var Member = require('./Member.js');

/**
 * The class representing a chain with which the client SDK interacts.
 */
var Chain = api.Chain.extend({

    // Name of the chain is only meaningful to the client
    _name: "",

    // The peers on this chain to which the client can connect
    _peers: [], // Peer[]

    // Security enabled flag
    _securityEnabled: true,

    // A member cache associated with this chain
    // TODO: Make an LRU to limit size of member cache
    _members: {}, // associated array of [name] <-> Member

    // The number of tcerts to get in each batch
    _tcertBatchSize: 200,

    // The registrar (if any) that registers & enrolls new members/users
    _registrar: null, // Member

    // The member services used for this chain
    _memberServices: null, // MemberServices

    // The key-val store used for this chain
    _keyValStore: null, // KeyValStore;

    // Is in dev mode or network mode
    _devMode: false,

    // If in prefetch mode, we prefetch tcerts from member services to help performance
    _preFetchMode: true,

    // Temporary variables to control how long to wait for deploy and invoke to complete before
    // emitting events.  This will be removed when the SDK is able to receive events from the
    _deployWaitTime: 20,
    _invokeWaitTime: 5,

    // The crypto primitives object
    _cryptoPrimitives: utils.getCryptoSuite(),

    constructor: function(name) {
        this._name = name;
    },

    /**
     * Get the chain name.
     * @returns The name of the chain.
     */
    getName: function() {
        return this._name;
    },

    /**
     * Add a peer given an endpoint specification.
     * @param endpoint The endpoint of the form: { url: "grpcs://host:port", tls: { .... } }
     * @returns {Peer} Returns a new peer.
     */
    addPeer: function(url, pem) {
        var peer = new Peer(url, this, pem);
        this._peers.push(peer);
        return peer;
    },

    /**
     * Get the peers for this chain.
     */
    getPeers: function() {
        return this._peers;
    },

    /**
     * Get the member whose credentials are used to register and enroll other users, or undefined if not set.
     * @param {Member} The member whose credentials are used to perform registration, or undefined if not set.
     */
    getRegistrar: function() {
        return this._registrar;
    },

    /**
     * Set the member whose credentials are used to register and enroll other users.
     * @param {Member} registrar The member whose credentials are used to perform registration.
     */
    setRegistrar: function(registrar) {
        this._registrar = registrar;
    },

    /**
     * Set the member services URL
     * @param {string} url Member services URL of the form: "grpc://host:port" or "grpcs://host:port"
     */
    setMemberServicesUrl: function(url, pem) {
        this.setMemberServices(new MemberServices(url, pem));
    },

    /**
     * Get the member service associated this chain.
     * @returns {MemberService} Return the current member service, or undefined if not set.
     */
    getMemberServices: function() {
        return this._memberServices;
    },

    /**
     * Set the member service associated this chain.  This allows the default implementation of member service to be overridden.
     */
    setMemberServices: function(memberServices) {
        this._memberServices = memberServices;
        if (memberServices instanceof MemberServices) {
            this._cryptoPrimitives = memberServices.getCrypto();
        }
    },

    /**
     * Determine if security is enabled.
     */
    isSecurityEnabled: function() {
        return this._memberServices !== undefined;
    },

    /**
     * Determine if pre-fetch mode is enabled to prefetch tcerts.
     */
    isPreFetchMode: function() {
        return this._preFetchMode;
    },

    /**
     * Set prefetch mode to true or false.
     */
    setPreFetchMode: function(preFetchMode) {
        this._preFetchMode = preFetchMode;
    },

    /**
     * Determine if dev mode is enabled.
     */
    isDevMode: function() {
        return this._devMode
    },

    /**
     * Set dev mode to true or false.
     */
    setDevMode: function(devMode) {
        this._devMode = devMode;
    },

    /**
     * Get the deploy wait time in seconds.
     */
    getDeployWaitTime: function() {
        return this._deployWaitTime;
    },

    /**
     * Set the deploy wait time in seconds.
     * Node.js will automatically enforce a
     * minimum and maximum wait time.  If the
     * number of seconds is larger than 2147483,
     * less than 1, or not a number,
     * the actual wait time used will be 1 ms.
     * @param secs
     */
    setDeployWaitTime: function(secs) {
        this._deployWaitTime = secs;
    },

    /**
     * Get the invoke wait time in seconds.
     */
    getInvokeWaitTime: function() {
        return this._invokeWaitTime;
    },

    /**
     * Set the invoke wait time in seconds.
     * @param secs
     */
    setInvokeWaitTime: function(secs) {
        this._invokeWaitTime = secs;
    },

    /**
     * Get the key val store implementation (if any) that is currently associated with this chain.
     * @returns {KeyValStore} Return the current KeyValStore associated with this chain, or undefined if not set.
     */
    getKeyValStore: function() {
        return this._keyValStore;
    },

    /**
     * Set the key value store implementation.
     */
    setKeyValStore: function(keyValStore) {
        this._keyValStore = keyValStore;
    },

    /**
     * Get the tcert batch size.
     */
    getTCertBatchSize: function() {
        return this._tcertBatchSize;
    },

    /**
     * Set the tcert batch size.
     */
    setTCertBatchSize: function(batchSize) {
        this._tcertBatchSize = batchSize;
    },

    /**
     * Get the user member named 'name' or create
     * a new member if the member does not exist.
     * @returns Promise for the Member object
     */
    getMember: function(name) {
        var self = this;
        return new Promise(function(resolve, reject) {
            if (!self._keyValStore) {
                reject(new Error("No key value store was found.  You must first call Chain.configureKeyValStore or Chain.setKeyValStore"));
            }

            if (!self._memberServices) {
                reject(new Error("No member services was found.  You must first call Chain.configureMemberServices or Chain.setMemberServices"));
            }

            self._getMemberHelper(name).then(
                function(member) {

                    resolve(member);

                },
                function(err) {

                    reject(err);

                }
            );
        });
    },

    /**
     * Get a user.
     * A user is a specific type of member.
     * Another type of member is a peer.
     * @returns Promise for the Member object
     */
    getUser: function(name) {
        return this.getMember(name);
    },

    // Try to get the member from cache.
    // If not found, create a new one.
    // If member is found in the key value store,
    //    restore the state to the new member, store in cache and return the member.
    // If there are no errors and member is not found in the key value store,
    //    return the new member.
    _getMemberHelper(name) {
        var self = this;

        return new Promise(function(resolve, reject) {
            // Try to get the member state from the cache
            var member = self._members[name];
            if (member) {
                resolve(member);
            }

            // Create the member and try to restore it's state from the key value store (if found).
            member = new Member(name, self);
            member.restoreState()
            .then(
                function() {
                    self._members[name] = member;
                    
                    resolve(member);
                },
                function(err) {
                    reject(err);
                }
            );
        });
    },

    /**
     * Register a user or other member type with the chain.
     * @param registrationRequest Registration information.
     * @returns Promise for a "true" status on successful registration
     */
    register(registrationRequest) {
        
        var self = this;

        return new Promise(function(resolve, reject) {
            self.getMember(registrationRequest.enrollmentID)
            .then(
                function(member) {                
                    member.register(registrationRequest);
                    resolve(true);
                },
                function(err) {
                    reject(err);
                }
            );
        });
    },

    /**
     * Enroll a user or other identity which has already been registered.
     * If the user has already been enrolled, this will still succeed.
     * @param name The name of the user or other member to enroll.
     * @param secret The secret of the user or other member to enroll.
     * @param cb The callback to return the user or other member.
     */
    enroll(name, secret) {
        var self = this;

        return new Promise(function(resolve, reject) {
            var _member;
            self.getMember(name)
            .then(
                function(member) {
                    _member = member;
                    return member.enroll(secret);
                },
                function(err) {
                    reject(err);
                }
            ).then(
                function() {
                    resolve(_member);
                },
                function(err) {
                    reject(err);
                }
            );
        });
    },

    /**
     * Register and enroll a user or other member type.
     * This assumes that a registrar with sufficient privileges has been set.
     * @param registrationRequest Registration information.
     * @params
     */
    registerAndEnroll(registrationRequest) {
        var self = this;

        return new Promise(function(resolve, reject) {
            self.getMember(registrationRequest.enrollmentID)
            .then(
                function(member) {
                    if (member.isEnrolled()) {
                        debug("already enrolled");
                        resolve(member);
                    }

                    member.registerAndEnroll(registrationRequest)
                    .then(
                        function() {
                            resolve(member);
                        },
                        function(err) {
                            reject(err);
                        }
                    );
                },
                function(err) {
                    reject(err);
                }
            );
        });
    },

    /**
     * Send a transaction to a peer.
     * @param tx A transaction
     * @param eventEmitter An event emitter
     */
    sendTransaction(tx, eventEmitter) {
        if (this._peers.length === 0) {
            return eventEmitter.emit('error', new Error(util.format("chain %s has no peers", this.getName())));
        }

        var peers = this._peers;

        var trySendTransaction = (pidx) => {
            if (pidx >= peers.length) {
                eventEmitter.emit('error', new Error("None of " + peers.length + " peers reponding"));
                return;
            }

            var p = urlParser.parse(peers[pidx].getUrl());
            var client = new net.Socket();
            
            var tryNext = () => {
                debug("Skipping unresponsive peer " + peers[pidx].getUrl());
                client.destroy();
                trySendTransaction(pidx + 1);
            }

            client.on('timeout', tryNext);
            client.on('error', tryNext);
            
            client.connect(p.port, p.hostname, () => {
                if (pidx > 0 && peers === this._peers)
                    this._peers = peers.slice(pidx).concat(peers.slice(0, pidx));

                client.destroy();
                
                peers[pidx].sendTransaction(tx, eventEmitter);
            });
        }

        trySendTransaction(0);
    }
});

module.exports = Chain;
