/**
 * Copyright 2016 IBM
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
/**
 * Licensed Materials - Property of IBM
 * © Copyright IBM Corp. 2016
 */

/**
 * "hfc" stands for "Hyperledger Fabric Client".
 * The Hyperledger Fabric Client SDK provides APIs through which a client can interact with a Hyperledger Fabric blockchain.
 *
 * Terminology:
 * 1) member - an identity for participating in the blockchain.  There are different types of members (users, peers, etc).
 * 2) member services - services related to obtaining and managing members
 * 3) registration - The act of adding a new member identity (with specific privileges) to the system.
 *               This is done by a member with the 'registrar' privilege.  The member is called a registrar.
 *               The registrar specifies the new member privileges when registering the new member.
 * 4) enrollment - Think of this as completing the registration process.  It may be done by the new member with a secret
 *               that it has obtained out-of-band from a registrar, or it may be performed by a middle-man who has
 *               delegated authority to act on behalf of the new member.
 *
 * These APIs have been designed to support two pluggable components.
 * 1) Pluggable key value store which is used to retrieve and store keys associated with a member.
 *    Call Chain.setKeyValueStore() to override the default key value store implementation.
 *    For the default implementations, see FileKeyValueStore and SqlKeyValueStore (TBD).
 * 2) Pluggable member service which is used to register and enroll members.
 *    Call Chain.setMemberService() to override the default implementation.
 *    For the default implementation, see MemberServices.
 *    NOTE: This makes member services pluggable from the client side, but more work is needed to make it compatible on
 *          the server side transaction processing path.
 */

// Instruct boringssl to use ECC for tls.
process.env['GRPC_SSL_CIPHER_SUITES'] = 'HIGH+ECDSA';

var debugModule = require('debug');
var fs = require('fs');
var urlParser = require('url');
var grpc = require('grpc');
var util = require('util');
var elliptic = require('elliptic');
var sha3 = require('js-sha3');
var BN = require('bn.js');
import * as crypto from "./crypto"
import * as stats from "./stats"
import * as sdk_util from "./sdk_util"
import events = require('events');

let debug = debugModule('hfc');   // 'hfc' stands for 'Hyperledger Fabric Client'
var asn1Builder = require('asn1');

let _fabricProto = grpc.load(__dirname + "/protos/fabric.proto").protos;
let _chaincodeProto = grpc.load(__dirname + "/protos/chaincode.proto").protos;

let CONFIDENTIALITY_1_2_STATE_KD_C6 = 6;

let _chains = {};




// This is the object that is delivered as the result with the "submitted" event
// from a Transaction object for a **deploy** operation.
export class EventDeploySubmitted {
    // The transaction ID of a deploy transaction which was successfully submitted.
    constructor(public uuid:string, public chaincodeID:string){};
}

// This is the object that is delivered as the result with the "complete" event
// from a Transaction object for a **deploy** operation.
// TODO: This class may change once the real event processing is added.
export class EventDeployComplete {
    constructor(public uuid:string, public chaincodeID:string, public result?:any){};
}

// This is the data that is delivered as the result with the "submitted" event
// from a Transaction object for an **invoke** operation.
export class EventInvokeSubmitted {
    // The transaction ID of an invoke transaction which was successfully submitted.
    constructor(public uuid:string){};
}

// This is the object that is delivered as the result with the "complete" event
// from a Transaction object for a **invoke** operation.
// TODO: This class may change once the real event processing is added.
export class EventInvokeComplete {
    constructor(public result?:any){};
}

// This is the object that is delivered as the result with the "complete" event
// from a Transaction object for a **query** operation.
export class EventQueryComplete {
    constructor(public result?:any){};
}

// This is the data that is delivered as the result with the "error" event
// from a Transaction object for any of the following operations:
// **deploy**, **invoke**, or **query**.
export class EventTransactionError {
    public msg:string;
    // The transaction ID of an invoke transaction which was successfully submitted.
    constructor(public error:any){
       if (error && error.msg && isFunction(error.msg.toString)) {
          this.msg = error.msg.toString();
       } else if (isFunction(error.toString)) {
          this.msg = error.toString();
       }
    };
}

// This is the data that is delivered as the result with the 'submitted' event
// from a TransactionContext object.
export interface SubmittedTransactionResponse {
    // The transaction ID of a transaction which was successfully submitted.
    uuid:string;
}



/**
 * A base transaction request common for DeployRequest, InvokeRequest, and QueryRequest.
 */
export interface TransactionRequest {
    // The chaincode ID as provided by the 'submitted' event emitted by a TransactionContext
    chaincodeID:string;
    // The name of the function to invoke
    fcn:string;
    // The arguments to pass to the chaincode invocation
    args:string[];
    // Specify whether the transaction is confidential or not.  The default value is false.
    confidential?:boolean,
    // Optionally provide a user certificate which can be used by chaincode to perform access control
    userCert?:Certificate;
    // Optionally provide additional metadata
    metadata?:Buffer
}

/**
 * Deploy request.
 */
export interface DeployRequest extends TransactionRequest {
    // The local path containing the chaincode to deploy in network mode.
    chaincodePath:string;
    // The name identifier for the chaincode to deploy in development mode.
    chaincodeName:string;
}

/**
 * Invoke or query request.
 */
export interface InvokeOrQueryRequest extends TransactionRequest {
    // Optionally pass a list of attributes which can be used by chaincode to perform access control
    attrs?:string[];
}

/**
 * Query request.
 */
export interface QueryRequest extends InvokeOrQueryRequest {
}

/**
 * Invoke request.
 */
export interface InvokeRequest extends InvokeOrQueryRequest {
}

/**
 * A transaction.
 */
export interface TransactionProtobuf {
    getType():string;
    setCert(cert:Buffer):void;
    setSignature(sig:Buffer):void;
    setConfidentialityLevel(value:number): void;
    getConfidentialityLevel(): number;
    setConfidentialityProtocolVersion(version:string):void;
    setNonce(nonce:Buffer):void;
    setToValidators(Buffer):void;
    getChaincodeID():{buffer: Buffer};
    setChaincodeID(buffer:Buffer):void;
    getMetadata():{buffer: Buffer};
    setMetadata(buffer:Buffer):void;
    getPayload():{buffer: Buffer};
    setPayload(buffer:Buffer):void;
    toBuffer():Buffer;
}

export class Transaction {
    constructor(public pb:TransactionProtobuf, public chaincodeID:string){};
}






/**
 * A transaction context emits events 'submitted', 'complete', and 'error'.
 * Each transaction context uses exactly one tcert.
 */
export class TransactionContext extends events.EventEmitter {

    private member:Member;
    private chain:Chain;
    private memberServices:MemberServices;
    private nonce: any;
    private binding: any;
    private tcert:TCert;
    private attrs:string[];

    constructor(member:Member, tcert:TCert) {
        super();
        this.member = member;
        this.chain = member.getChain();
        this.memberServices = this.chain.getMemberServices();
        this.tcert = tcert;
        this.nonce = this.chain.cryptoPrimitives.generateNonce();
    }

    /**
     * Get the member with which this transaction context is associated.
     * @returns The member
     */
    getMember():Member {
        return this.member;
    }

    /**
     * Get the chain with which this transaction context is associated.
     * @returns The chain
     */
    getChain():Chain {
        return this.chain;
    };

    /**
     * Get the member services, or undefined if security is not enabled.
     * @returns The member services
     */
    getMemberServices():MemberServices {
        return this.memberServices;
    };

    /**
     * Emit a specific event provided an event listener is already registered.
     */
    emitMyEvent(name:string, event:any) {
       var self = this;

       setTimeout(function() {
         // Check if an event listener has been registered for the event
         let listeners = self.listeners(name);

         // If an event listener has been registered, emit the event
         if (listeners && listeners.length > 0) {
            self.emit(name, event);
         }
       }, 0);
    }

    /**
     * Issue a deploy transaction.
     * @param deployRequest {Object} A deploy request of the form: { chaincodeID, payload, metadata, uuid, timestamp, confidentiality: { level, version, nonce }
   */
    deploy(deployRequest:DeployRequest):TransactionContext {
        debug("TransactionContext.deploy");
        debug("Received deploy request: %j", deployRequest);

        let self = this;

        // Get a TCert to use in the deployment transaction
        self.getMyTCert(function (err) {
            if (err) {
                debug('Failed getting a new TCert [%s]', err);
                self.emitMyEvent('error', new EventTransactionError(err));

                return self;
            }

            debug("Got a TCert successfully, continue...");

            self.newBuildOrDeployTransaction(deployRequest, false, function(err, deployTx) {
              if (err) {
                debug("Error in newBuildOrDeployTransaction [%s]", err);
                self.emitMyEvent('error', new EventTransactionError(err));

                return self;
              }

              debug("Calling TransactionContext.execute");

              return self.execute(deployTx);
            });
        });
        return self;
    }

    /**
     * Issue an invoke transaction.
     * @param invokeRequest {Object} An invoke request of the form: XXX
     */
    invoke(invokeRequest:InvokeRequest):TransactionContext {
        debug("TransactionContext.invoke");
        debug("Received invoke request: %j", invokeRequest);

        let self = this;

        // Get a TCert to use in the invoke transaction
        self.setAttrs(invokeRequest.attrs);
        self.getMyTCert(function (err, tcert) {
            if (err) {
                debug('Failed getting a new TCert [%s]', err);
                self.emitMyEvent('error', new EventTransactionError(err));

                return self;
            }

            debug("Got a TCert successfully, continue...");

            self.newInvokeOrQueryTransaction(invokeRequest, true, function(err, invokeTx) {
              if (err) {
                debug("Error in newInvokeOrQueryTransaction [%s]", err);
                self.emitMyEvent('error', new EventTransactionError(err));

                return self;
              }

              debug("Calling TransactionContext.execute");

              return self.execute(invokeTx);
            });
        });
        return self;
    }

    /**
     * Issue an query transaction.
     * @param queryRequest {Object} A query request of the form: XXX
     */
    query(queryRequest:QueryRequest):TransactionContext {
      debug("TransactionContext.query");
      debug("Received query request: %j", queryRequest);

      let self = this;

      // Get a TCert to use in the query transaction
      self.setAttrs(queryRequest.attrs);
      self.getMyTCert(function (err, tcert) {
          if (err) {
              debug('Failed getting a new TCert [%s]', err);
              self.emitMyEvent('error', new EventTransactionError(err));

              return self;
          }

          debug("Got a TCert successfully, continue...");

          self.newInvokeOrQueryTransaction(queryRequest, false, function(err, queryTx) {
            if (err) {
              debug("Error in newInvokeOrQueryTransaction [%s]", err);
              self.emitMyEvent('error', new EventTransactionError(err));

              return self;
            }

            debug("Calling TransactionContext.execute");

            return self.execute(queryTx);
          });
        });
      return self;
    }

   /**
    * Get the attribute names associated
    */
   getAttrs(): string[] {
       return this.attrs;
   }

   /**
    * Set the attributes for this transaction context.
    */
   setAttrs(attrs:string[]): void {
       this.attrs = attrs;
   }

    /**
     * Execute a transaction
     * @param tx {Transaction} The transaction.
     */
    private execute(tx:Transaction):TransactionContext {
        debug('Executing transaction [%j]', tx);

        let self = this;
        // Get the TCert
        self.getMyTCert(function (err, tcert) {
            if (err) {
                debug('Failed getting a new TCert [%s]', err);
                return self.emit('error', new EventTransactionError(err));
            }

            if (tcert) {
                // Set nonce
                tx.pb.setNonce(self.nonce);

                // Process confidentiality
                debug('Process Confidentiality...');

                self.processConfidentiality(tx);

                debug('Sign transaction...');

                // Add the tcert
                tx.pb.setCert(tcert.publicKey);
                // sign the transaction bytes
                let txBytes = tx.pb.toBuffer();
                let derSignature = self.chain.cryptoPrimitives.ecdsaSign(tcert.privateKey.getPrivate('hex'), txBytes).toDER();
                // debug('signature: ', derSignature);
                tx.pb.setSignature(new Buffer(derSignature));

                debug('Send transaction...');
                debug('Confidentiality: ', tx.pb.getConfidentialityLevel());

                if (tx.pb.getConfidentialityLevel() == _fabricProto.ConfidentialityLevel.CONFIDENTIAL &&
                        tx.pb.getType() == _fabricProto.Transaction.Type.CHAINCODE_QUERY) {
                    // Need to send a different event emitter so we can catch the response
                    // and perform decryption before sending the real complete response
                    // to the caller
                    var emitter = new events.EventEmitter();
                    emitter.on("complete", function (event:EventQueryComplete) {
                        debug("Encrypted: [%j]", event);
                        event.result = self.decryptResult(event.result);
                        debug("Decrypted: [%j]", event);
                        self.emit("complete", event);
                    });
                    emitter.on("error", function (event:EventTransactionError) {
                        self.emit("error", event);
                    });
                    self.getChain().sendTransaction(tx, emitter);
                } else {
                    self.getChain().sendTransaction(tx, self);
                }
            } else {
                debug('Missing TCert...');
                return self.emit('error', new EventTransactionError('Missing TCert.'));
            }

        });
        return self;
    }

    private getMyTCert(cb:GetTCertCallback): void {
        let self = this;
        if (!self.getChain().isSecurityEnabled() || self.tcert) {
            debug('[TransactionContext] TCert already cached.');
            return cb(null, self.tcert);
        }
        debug('[TransactionContext] No TCert cached. Retrieving one.');
        this.member.getNextTCert(self.attrs, function (err, tcert) {
            if (err) return cb(err);
            self.tcert = tcert;
            return cb(null, tcert);
        });
    }

    private processConfidentiality(transaction:Transaction) {
        // is confidentiality required?
        if (transaction.pb.getConfidentialityLevel() != _fabricProto.ConfidentialityLevel.CONFIDENTIAL) {
            // No confidentiality is required
            return
        }

        debug('Process Confidentiality ...');
        var self = this;

        // Set confidentiality level and protocol version
        transaction.pb.setConfidentialityProtocolVersion('1.2');

        // Generate transaction key. Common to all type of transactions
        var txKey = self.chain.cryptoPrimitives.eciesKeyGen();

        debug('txkey [%j]', txKey.pubKeyObj.pubKeyHex);
        debug('txKey.prvKeyObj %j', txKey.prvKeyObj.toString());

        var privBytes = self.chain.cryptoPrimitives.ecdsaPrivateKeyToASN1(txKey.prvKeyObj.prvKeyHex);
        debug('privBytes %s', privBytes.toString());

        // Generate stateKey. Transaction type dependent step.
        var stateKey;
        if (transaction.pb.getType() == _fabricProto.Transaction.Type.CHAINCODE_DEPLOY) {
            // The request is for a deploy
            stateKey = new Buffer(self.chain.cryptoPrimitives.aesKeyGen());
        } else if (transaction.pb.getType() == _fabricProto.Transaction.Type.CHAINCODE_INVOKE ) {
            // The request is for an execute
            // Empty state key
            stateKey = new Buffer([]);
        } else {
            // The request is for a query
            debug('Generate state key...');
            stateKey = new Buffer(self.chain.cryptoPrimitives.hmacAESTruncated(
                self.member.getEnrollment().queryStateKey,
                [CONFIDENTIALITY_1_2_STATE_KD_C6].concat(self.nonce)
            ));
        }

        // Prepare ciphertexts

        // Encrypts message to validators using self.enrollChainKey
        var chainCodeValidatorMessage1_2 = new asn1Builder.Ber.Writer();
        chainCodeValidatorMessage1_2.startSequence();
        chainCodeValidatorMessage1_2.writeBuffer(privBytes, 4);
        if (stateKey.length != 0) {
            debug('STATE KEY %j', stateKey);
            chainCodeValidatorMessage1_2.writeBuffer(stateKey, 4);
        } else {
            chainCodeValidatorMessage1_2.writeByte(4);
            chainCodeValidatorMessage1_2.writeLength(0);
        }
        chainCodeValidatorMessage1_2.endSequence();
        debug(chainCodeValidatorMessage1_2.buffer);

        debug('Using chain key [%j]', self.member.getEnrollment().chainKey);
        var ecdsaChainKey = self.chain.cryptoPrimitives.ecdsaPEMToPublicKey(
            self.member.getEnrollment().chainKey
        );

        let encMsgToValidators = self.chain.cryptoPrimitives.eciesEncryptECDSA(
            ecdsaChainKey,
            chainCodeValidatorMessage1_2.buffer
        );
        transaction.pb.setToValidators(encMsgToValidators);

        // Encrypts chaincodeID using txKey
        // debug('CHAINCODE ID %j', transaction.chaincodeID);

        let encryptedChaincodeID = self.chain.cryptoPrimitives.eciesEncrypt(
            txKey.pubKeyObj,
            transaction.pb.getChaincodeID().buffer
        );
        transaction.pb.setChaincodeID(encryptedChaincodeID);

        // Encrypts payload using txKey
        // debug('PAYLOAD ID %j', transaction.payload);
        let encryptedPayload = self.chain.cryptoPrimitives.eciesEncrypt(
            txKey.pubKeyObj,
            transaction.pb.getPayload().buffer
        );
        transaction.pb.setPayload(encryptedPayload);

        // Encrypt metadata using txKey
        if (transaction.pb.getMetadata() != null && transaction.pb.getMetadata().buffer != null) {
            debug('Metadata [%j]', transaction.pb.getMetadata().buffer);
            let encryptedMetadata = self.chain.cryptoPrimitives.eciesEncrypt(
                txKey.pubKeyObj,
                transaction.pb.getMetadata().buffer
            );
            transaction.pb.setMetadata(encryptedMetadata);
        }
    }

    private decryptResult(ct:Buffer) {
        let key = new Buffer(
            this.chain.cryptoPrimitives.hmacAESTruncated(
                this.member.getEnrollment().queryStateKey,
                [CONFIDENTIALITY_1_2_STATE_KD_C6].concat(this.nonce))
        );

        debug('Decrypt Result [%s]', ct.toString('hex'));
        return this.chain.cryptoPrimitives.aes256GCMDecrypt(key, ct);
    }

    /**
     * Create a deploy transaction.
     * @param request {Object} A BuildRequest or DeployRequest
     */
    private newBuildOrDeployTransaction(request:DeployRequest, isBuildRequest:boolean, cb:DeployTransactionCallback):void {
      	debug("newBuildOrDeployTransaction");

        let self = this;

        // Determine if deployment is for dev mode or net mode
        if (self.chain.isDevMode()) {
            // Deployment in developent mode. Build a dev mode transaction.
            this.newDevModeTransaction(request, isBuildRequest, function(err, tx) {
                if(err) {
                    return cb(err);
                } else {
                    return cb(null, tx);
                }
            });
        } else {
            // Deployment in network mode. Build a net mode transaction.
            this.newNetModeTransaction(request, isBuildRequest, function(err, tx) {
                if(err) {
                    return cb(err);
                } else {
                    return cb(null, tx);
                }
            });
        }
    } // end newBuildOrDeployTransaction

    /**
     * Create a development mode deploy transaction.
     * @param request {Object} A development mode BuildRequest or DeployRequest
     */
    private newDevModeTransaction(request:DeployRequest, isBuildRequest:boolean, cb:DeployTransactionCallback):void {
        debug("newDevModeTransaction");

        let self = this;

        // Verify that chaincodeName is being passed
        if (!request.chaincodeName || request.chaincodeName === "") {
          return cb(Error("missing chaincodeName in DeployRequest"));
        }

        let tx = new _fabricProto.Transaction();

        if (isBuildRequest) {
            tx.setType(_fabricProto.Transaction.Type.CHAINCODE_BUILD);
        } else {
            tx.setType(_fabricProto.Transaction.Type.CHAINCODE_DEPLOY);
        }

        // Set the chaincodeID
        let chaincodeID = new _chaincodeProto.ChaincodeID();
        chaincodeID.setName(request.chaincodeName);
        debug("newDevModeTransaction: chaincodeID: " + JSON.stringify(chaincodeID));
        tx.setChaincodeID(chaincodeID.toBuffer());

        // Construct the ChaincodeSpec
        let chaincodeSpec = new _chaincodeProto.ChaincodeSpec();
        // Set Type -- GOLANG is the only chaincode language supported at this time
        chaincodeSpec.setType(_chaincodeProto.ChaincodeSpec.Type.GOLANG);
        // Set chaincodeID
        chaincodeSpec.setChaincodeID(chaincodeID);
        // Set ctorMsg
        let chaincodeInput = new _chaincodeProto.ChaincodeInput();
        chaincodeInput.setArgs(prepend(request.fcn, request.args));
        chaincodeSpec.setCtorMsg(chaincodeInput);

        // Construct the ChaincodeDeploymentSpec (i.e. the payload)
        let chaincodeDeploymentSpec = new _chaincodeProto.ChaincodeDeploymentSpec();
        chaincodeDeploymentSpec.setChaincodeSpec(chaincodeSpec);
        tx.setPayload(chaincodeDeploymentSpec.toBuffer());

        // Set the transaction UUID
        tx.setTxid(request.chaincodeName);

        // Set the transaction timestamp
        tx.setTimestamp(sdk_util.GenerateTimestamp());

        // Set confidentiality level
        if (request.confidential) {
            debug("Set confidentiality level to CONFIDENTIAL");
            tx.setConfidentialityLevel(_fabricProto.ConfidentialityLevel.CONFIDENTIAL);
        } else {
            debug("Set confidentiality level to PUBLIC");
            tx.setConfidentialityLevel(_fabricProto.ConfidentialityLevel.PUBLIC);
        }

        // Set request metadata
        if (request.metadata) {
            tx.setMetadata(request.metadata);
        }

        // Set the user certificate data
        if (request.userCert) {
            // cert based
            let certRaw = new Buffer(self.tcert.publicKey);
            // debug('========== Invoker Cert [%s]', certRaw.toString('hex'));
            let nonceRaw = new Buffer(self.nonce);
            let bindingMsg = Buffer.concat([certRaw, nonceRaw]);
            // debug('========== Binding Msg [%s]', bindingMsg.toString('hex'));
            this.binding = new Buffer(self.chain.cryptoPrimitives.hash(bindingMsg), 'hex');
            // debug('========== Binding [%s]', this.binding.toString('hex'));
            let ctor = chaincodeSpec.getCtorMsg().toBuffer();
            // debug('========== Ctor [%s]', ctor.toString('hex'));
            let txmsg = Buffer.concat([ctor, this.binding]);
            // debug('========== Payload||binding [%s]', txmsg.toString('hex'));
            let mdsig = self.chain.cryptoPrimitives.ecdsaSign(request.userCert.privateKey.getPrivate('hex'), txmsg);
            let sigma = new Buffer(mdsig.toDER());
            // debug('========== Sigma [%s]', sigma.toString('hex'));
            tx.setMetadata(sigma);
        }

        tx = new Transaction(tx, request.chaincodeName);

        return cb(null, tx);
    }

    /**
     * Create a network mode deploy transaction.
     * @param request {Object} A network mode BuildRequest or DeployRequest
     */
    private newNetModeTransaction(request:DeployRequest, isBuildRequest:boolean, cb:DeployTransactionCallback):void {
        debug("newNetModeTransaction");

        let self = this;

        // Verify that chaincodePath is being passed
        if (!request.chaincodePath || request.chaincodePath === "") {
          return cb(Error("missing chaincodePath in DeployRequest"));
        }

        // Determine the user's $GOPATH
        let goPath =  process.env['GOPATH'];
        debug("$GOPATH: " + goPath);

        // Compose the path to the chaincode project directory
        let projDir = goPath + "/src/" + request.chaincodePath;
        debug("projDir: " + projDir);

        // Compute the hash of the chaincode deployment parameters
        let hash = sdk_util.GenerateParameterHash(request.chaincodePath, request.fcn, request.args);

        // Compute the hash of the project directory contents
        hash = sdk_util.GenerateDirectoryHash(goPath + "/src/", request.chaincodePath, hash);
        debug("hash: " + hash);

        // Compose the Dockerfile commands
     	  let dockerFileContents =
        "from hyperledger/fabric-baseimage" + "\n" +
     	  "COPY . $GOPATH/src/build-chaincode/" + "\n" +
     	  "WORKDIR $GOPATH" + "\n\n" +
     	  "RUN go install build-chaincode && cp src/build-chaincode/vendor/github.com/hyperledger/fabric/peer/core.yaml $GOPATH/bin && mv $GOPATH/bin/build-chaincode $GOPATH/bin/%s";

     	  // Substitute the hashStrHash for the image name
     	  dockerFileContents = util.format(dockerFileContents, hash);

     	  // Create a Docker file with dockerFileContents
     	  let dockerFilePath = projDir + "/Dockerfile";
     	  fs.writeFile(dockerFilePath, dockerFileContents, function(err) {
            if (err) {
                debug(util.format("Error writing file [%s]: %s", dockerFilePath, err));
                return cb(Error(util.format("Error writing file [%s]: %s", dockerFilePath, err)));
            }

            debug("Created Dockerfile at [%s]", dockerFilePath);

            // Create the .tar.gz file of the chaincode package
            let targzFilePath = "/tmp/deployment-package.tar.gz";
            // Create the compressed archive
            sdk_util.GenerateTarGz(projDir, targzFilePath, function(err) {
                if(err) {
                    debug(util.format("Error creating deployment archive [%s]: %s", targzFilePath, err));
                    return cb(Error(util.format("Error creating deployment archive [%s]: %s", targzFilePath, err)));
                }

                debug(util.format("Created deployment archive at [%s]", targzFilePath));

                //
                // Initialize a transaction structure
                //

                let tx = new _fabricProto.Transaction();

                //
                // Set the transaction type
                //

                if (isBuildRequest) {
                    tx.setType(_fabricProto.Transaction.Type.CHAINCODE_BUILD);
                } else {
                    tx.setType(_fabricProto.Transaction.Type.CHAINCODE_DEPLOY);
                }

                //
                // Set the chaincodeID
                //

                let chaincodeID = new _chaincodeProto.ChaincodeID();
                chaincodeID.setName(hash);
                debug("chaincodeID: " + JSON.stringify(chaincodeID));
                tx.setChaincodeID(chaincodeID.toBuffer());

                //
                // Set the payload
                //

                // Construct the ChaincodeSpec
                let chaincodeSpec = new _chaincodeProto.ChaincodeSpec();

                // Set Type -- GOLANG is the only chaincode language supported at this time
                chaincodeSpec.setType(_chaincodeProto.ChaincodeSpec.Type.GOLANG);
                // Set chaincodeID
                chaincodeSpec.setChaincodeID(chaincodeID);
                // Set ctorMsg
                let chaincodeInput = new _chaincodeProto.ChaincodeInput();
                chaincodeInput.setArgs(prepend(request.fcn, request.args));
                chaincodeSpec.setCtorMsg(chaincodeInput);
                debug("chaincodeSpec: " + JSON.stringify(chaincodeSpec));

                // Construct the ChaincodeDeploymentSpec and set it as the Transaction payload
                let chaincodeDeploymentSpec = new _chaincodeProto.ChaincodeDeploymentSpec();
                chaincodeDeploymentSpec.setChaincodeSpec(chaincodeSpec);

                // Read in the .tar.zg and set it as the CodePackage in ChaincodeDeploymentSpec
                fs.readFile(targzFilePath, function(err, data) {
                    if(err) {
                        debug(util.format("Error reading deployment archive [%s]: %s", targzFilePath, err));
                        return cb(Error(util.format("Error reading deployment archive [%s]: %s", targzFilePath, err)));
                    }

                    debug(util.format("Read in deployment archive from [%s]", targzFilePath));

                    chaincodeDeploymentSpec.setCodePackage(data);
                    tx.setPayload(chaincodeDeploymentSpec.toBuffer());

                    //
                    // Set the transaction UUID
                    //

                    tx.setTxid(sdk_util.GenerateUUID());

                    //
                    // Set the transaction timestamp
                    //

                    tx.setTimestamp(sdk_util.GenerateTimestamp());

                    //
                    // Set confidentiality level
                    //

                    if (request.confidential) {
                        debug("Set confidentiality level to CONFIDENTIAL");
                        tx.setConfidentialityLevel(_fabricProto.ConfidentialityLevel.CONFIDENTIAL);
                    } else {
                        debug("Set confidentiality level to PUBLIC");
                        tx.setConfidentialityLevel(_fabricProto.ConfidentialityLevel.PUBLIC);
                    }

                    //
                    // Set request metadata
                    //

                    if (request.metadata) {
                        tx.setMetadata(request.metadata);
                    }

                    //
                    // Set the user certificate data
                    //

                    if (request.userCert) {
                        // cert based
                        let certRaw = new Buffer(self.tcert.publicKey);
                        // debug('========== Invoker Cert [%s]', certRaw.toString('hex'));
                        let nonceRaw = new Buffer(self.nonce);
                        let bindingMsg = Buffer.concat([certRaw, nonceRaw]);
                        // debug('========== Binding Msg [%s]', bindingMsg.toString('hex'));
                        self.binding = new Buffer(self.chain.cryptoPrimitives.hash(bindingMsg), 'hex');
                        // debug('========== Binding [%s]', self.binding.toString('hex'));
                        let ctor = chaincodeSpec.getCtorMsg().toBuffer();
                        // debug('========== Ctor [%s]', ctor.toString('hex'));
                        let txmsg = Buffer.concat([ctor, self.binding]);
                        // debug('========== Payload||binding [%s]', txmsg.toString('hex'));
                        let mdsig = self.chain.cryptoPrimitives.ecdsaSign(request.userCert.privateKey.getPrivate('hex'), txmsg);
                        let sigma = new Buffer(mdsig.toDER());
                        // debug('========== Sigma [%s]', sigma.toString('hex'));
                        tx.setMetadata(sigma);
                    }

                    //
                    // Clean up temporary files
                    //

                    // Remove the temporary .tar.gz with the deployment contents and the Dockerfile
                    fs.unlink(targzFilePath, function(err) {
                        if(err) {
                            debug(util.format("Error deleting temporary archive [%s]: %s", targzFilePath, err));
                            return cb(Error(util.format("Error deleting temporary archive [%s]: %s", targzFilePath, err)));
                        }

                        debug("Temporary archive deleted successfully ---> " + targzFilePath);

                        fs.unlink(dockerFilePath, function(err) {
                            if(err) {
                                debug(util.format("Error deleting temporary file [%s]: %s", dockerFilePath, err));
                                return cb(Error(util.format("Error deleting temporary file [%s]: %s", dockerFilePath, err)));
                            }

                            debug("File deleted successfully ---> " + dockerFilePath);

                            //
                            // Return the deploy transaction structure
                            //

                            tx = new Transaction(tx, hash);

                            return cb(null, tx);
                        }); // end delete Dockerfile
                    }); // end delete .tar.gz
              }); // end reading .tar.zg and composing transaction
	         }); // end writing .tar.gz
	      }); // end writing Dockerfile
    }

    /**
     * Create an invoke or query transaction.
     * @param request {Object} A build or deploy request of the form: { chaincodeID, payload, metadata, uuid, timestamp, confidentiality: { level, version, nonce }
     */
    private newInvokeOrQueryTransaction(request:InvokeOrQueryRequest, isInvokeRequest:boolean, cb:InvokeOrQueryTransactionCallback):void {
        let self = this;

        // Verify that chaincodeID is being passed
        if (!request.chaincodeID || request.chaincodeID === "") {
          return cb(Error("missing chaincodeID in InvokeOrQueryRequest"));
        }

        // Create a deploy transaction
        let tx = new _fabricProto.Transaction();
        if (isInvokeRequest) {
            tx.setType(_fabricProto.Transaction.Type.CHAINCODE_INVOKE);
        } else {
            tx.setType(_fabricProto.Transaction.Type.CHAINCODE_QUERY);
        }

        // Set the chaincodeID
        let chaincodeID = new _chaincodeProto.ChaincodeID();
        chaincodeID.setName(request.chaincodeID);
        debug("newInvokeOrQueryTransaction: request=%j, chaincodeID=%s", request, JSON.stringify(chaincodeID));
        tx.setChaincodeID(chaincodeID.toBuffer());

        // Construct the ChaincodeSpec
        let chaincodeSpec = new _chaincodeProto.ChaincodeSpec();
        // Set Type -- GOLANG is the only chaincode language supported at this time
        chaincodeSpec.setType(_chaincodeProto.ChaincodeSpec.Type.GOLANG);
        // Set chaincodeID
        chaincodeSpec.setChaincodeID(chaincodeID);
        // Set ctorMsg
        let chaincodeInput = new _chaincodeProto.ChaincodeInput();
        chaincodeInput.setArgs(prepend(request.fcn, request.args));
        chaincodeSpec.setCtorMsg(chaincodeInput);
        // Construct the ChaincodeInvocationSpec (i.e. the payload)
        let chaincodeInvocationSpec = new _chaincodeProto.ChaincodeInvocationSpec();
        chaincodeInvocationSpec.setChaincodeSpec(chaincodeSpec);
        tx.setPayload(chaincodeInvocationSpec.toBuffer());

        // Set the transaction UUID
        tx.setTxid(sdk_util.GenerateUUID());

        // Set the transaction timestamp
        tx.setTimestamp(sdk_util.GenerateTimestamp());

        // Set confidentiality level
        if (request.confidential) {
            debug('Set confidentiality on');
            tx.setConfidentialityLevel(_fabricProto.ConfidentialityLevel.CONFIDENTIAL)
        } else {
            debug('Set confidentiality on');
            tx.setConfidentialityLevel(_fabricProto.ConfidentialityLevel.PUBLIC)
        }

        if (request.metadata) {
            tx.setMetadata(request.metadata)
        }

        if (request.userCert) {
            // cert based
            let certRaw = new Buffer(self.tcert.publicKey);
            // debug('========== Invoker Cert [%s]', certRaw.toString('hex'));
            let nonceRaw = new Buffer(self.nonce);
            let bindingMsg = Buffer.concat([certRaw, nonceRaw]);
            // debug('========== Binding Msg [%s]', bindingMsg.toString('hex'));
            this.binding = new Buffer(self.chain.cryptoPrimitives.hash(bindingMsg), 'hex');
            // debug('========== Binding [%s]', this.binding.toString('hex'));
            let ctor = chaincodeSpec.getCtorMsg().toBuffer();
            // debug('========== Ctor [%s]', ctor.toString('hex'));
            let txmsg = Buffer.concat([ctor, this.binding]);
            // debug('========== Pyaload||binding [%s]', txmsg.toString('hex'));
            let mdsig = self.chain.cryptoPrimitives.ecdsaSign(request.userCert.privateKey.getPrivate('hex'), txmsg);
            let sigma = new Buffer(mdsig.toDER());
            // debug('========== Sigma [%s]', sigma.toString('hex'));
            tx.setMetadata(sigma)
        }

        tx = new Transaction(tx, request.chaincodeID);

        return cb(null, tx);
    }

}  // end TransactionContext








function newMemberServices(url,pem) {
    return new MemberServicesImpl(url,pem);
}



// Return a unique string value for the list of attributes.
function getAttrsKey(attrs?:string[]): string {
    if (!attrs) return "null";
    let key = "[]";
    for (let i = 0; i < attrs.length; i++) {
       key += "," + attrs[i];
    }
    return key;
}

// A null callback to use when the user doesn't pass one in
function nullCB():void {
}

// Determine if an object is a string
function isString(obj:any):boolean {
    return (typeof obj === 'string' || obj instanceof String);
}

// Determine if 'obj' is an object (not an array, string, or other type)
function isObject(obj:any):boolean {
    return (!!obj) && (obj.constructor === Object);
}

function isFunction(fcn:any):boolean {
    return (typeof fcn === 'function');
}


function endsWith(str:string, suffix:string) {
    return str.length >= suffix.length && str.substr(str.length - suffix.length) === suffix;
};

function prepend(item:string, list:string[]) {
    var l = list.slice();
    l.unshift(item);
    return l.map(function(x) { return new Buffer(x) });
};


/**
 * Create an instance of a FileKeyValueStore.
 */
export function newFileKeyValueStore(dir:string):KeyValueStore {
    return new FileKeyValueStore(dir);
}
