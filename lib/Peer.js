var api = require('./api.js');
var utils = require('./utils.js');
var grpc = require('grpc');

var _fabricProto = grpc.load(__dirname + "/protos/fabric.proto").protos;

/**
 * The Peer class represents a peer to which HFC sends deploy, invoke, or query requests.
 */
var Peer = api.Peer.extend({

    _url: "",
    _chain: null, //Chain
    _ep: null, // Endpoint
    _peerClient: null,

    /**
     * Constructs a Peer given its endpoint configuration settings
     * and returns the new Peer.
     * @param {string} url The URL with format of "grpcs://host:port".
     * @param {Chain} chain The chain of which this peer is a member.
     * @param {string} pem The certificate file, in PEM format,
     * to use with the gRPC protocol (that is, with TransportCredentials).
     * Required when using the grpcs protocol.
     * @returns {Peer} The new peer.
     */
    constructor: function(url, chain, pem) {
        this._url = url;
        this._chain = chain;
        this._ep = new utils.Endpoint(url,pem);
        this._peerClient = new _fabricProto.Peer(this._ep.addr, this._ep.creds);
    },

    /**
     * Get the chain of which this peer is a member.
     * @returns {Chain} The chain of which this peer is a member.
     */
    getChain: function() {
        return this._chain;
    },

    /**
     * Get the URL of the peer.
     * @returns {string} Get the URL associated with the peer.
     */
    getUrl: function() {
        return this._url;
    },

    /**
     * Send a transaction to this peer.
     * @param tx A transaction
     * @param eventEmitter The event emitter
     */
    sendTransaction: function(tx, eventEmitter) {
        var self = this;

        // Send the transaction to the peer node via grpc
        // The rpc specification on the peer side is:
        //     rpc ProcessTransaction(Transaction) returns (Response) {}
        self._peerClient.processTransaction(tx.pb, function (err, response) {
            if (err) {
                return eventEmitter.emit('error', new Error(err));
            }

            // Check transaction type here, as invoke is an asynchronous call,
            // whereas a deploy and a query are synchonous calls. As such,
            // invoke will emit 'submitted' and 'error', while a deploy/query
            // will emit 'complete' and 'error'.
            var txType = tx.pb.getType();
            switch (txType) {
               case _fabricProto.Transaction.Type.CHAINCODE_DEPLOY: // async
                  if (response.status === "SUCCESS") {
                     // Deploy transaction has been completed
                     if (!response.msg || response.msg === "") {
                        eventEmitter.emit("error", new Error("the deploy response is missing the transaction UUID"));
                     } else {
                        var event = {
                          uuid: response.msg.toString(), 
                          chaincodeID: tx.chaincodeID
                        };

                        eventEmitter.emit("submitted", event);
                        self._waitForDeployComplete(eventEmitter,event);
                     }
                  } else {
                     // Deploy completed with status "FAILURE" or "UNDEFINED"
                     eventEmitter.emit("error", new Error(response));
                  }
                  break;
               case _fabricProto.Transaction.Type.CHAINCODE_INVOKE: // async
                  if (response.status === "SUCCESS") {
                     // Invoke transaction has been submitted
                     if (!response.msg || response.msg === "") {
                        eventEmitter.emit("error", new Error("the invoke response is missing the transaction UUID"));
                     } else {
                        eventEmitter.emit("submitted", {uuid: response.msg.toString()});
                        self._waitForInvokeComplete(eventEmitter);
                     }
                  } else {
                     // Invoke completed with status "FAILURE" or "UNDEFINED"
                     eventEmitter.emit("error", new Error(response));
                  }
                  break;
               case _fabricProto.Transaction.Type.CHAINCODE_QUERY: // sync
                  if (response.status === "SUCCESS") {
                     // Query transaction has been completed
                     eventEmitter.emit("complete", {result: response.msg});
                  } else {
                     // Query completed with status "FAILURE" or "UNDEFINED"
                     eventEmitter.emit("error", new Error(response));
                  }
                  break;
               default: // not implemented
                  eventEmitter.emit("error", new Error("processTransaction for this transaction type is not yet implemented!"));
            }
          });
    },

    /**
     * TODO: Temporary hack to wait until the deploy event has hopefully completed.
     * This does not detect if an error occurs in the peer or chaincode when deploying.
     * When peer event listening is added to the SDK, this will be implemented correctly.
     */
    _waitForDeployComplete(eventEmitter, submitted) {
        var waitTime = this.chain.getDeployWaitTime();

        setTimeout(
           function() {
              var event = {
                  uuid: submitted.uuid,
                  chaincodeID: submitted.chaincodeID
              };

              eventEmitter.emit("complete",event);
           },
           waitTime * 1000
        );
    },

    /**
     * TODO: Temporary hack to wait until the deploy event has hopefully completed.
     * This does not detect if an error occurs in the peer or chaincode when deploying.
     * When peer event listening is added to the SDK, this will be implemented correctly.
     */
    _waitForInvokeComplete(eventEmitter) {
        var waitTime = this.chain.getInvokeWaitTime();

        setTimeout(
           function() {
              eventEmitter.emit("complete", {result: "waited "+waitTime+" seconds and assumed invoke was successful"});
           },
           waitTime * 1000
        );
    }
});

module.exports = Peer;
