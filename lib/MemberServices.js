var api = require('./api.js');
var utils = require('./utils');
var jsrsa = require('jsrsasign');
var asn1 = jsrsa.asn1;
var X509Certificate = require('./X509Certificate.js');

var CryptoSuite = utils.getCryptoSuite();

var grpc = require('grpc');
var _caProto = grpc.load(__dirname + "/protos/ca.proto").protos;


/**
 * MemberServicesImpl is the default implementation of a member services client.
 */
var MemberServices = api.MemberServices.extend({

    _ecaaClient: null,
    _ecapClient: null,
    _tcapClient: null,
    _tlscapClient: null,
    _cryptoPrimitives: null,

    /**
     * MemberServicesImpl constructor
     * @param config The config information required by this member services implementation.
     * @returns {MemberServices} A MemberServices object.
     */
    constructor: function(url /*string*/, pem /*string*/) {
        var ep = new utils.Endpoint(url,pem);
        var options = {
              'grpc.ssl_target_name_override' : 'tlsca',
              'grpc.default_authority': 'tlsca'
        };
        this._ecaaClient = new _caProto.ECAA(ep.addr, ep.creds, options);
        this._ecapClient = new _caProto.ECAP(ep.addr, ep.creds, options);
        this._tcapClient = new _caProto.TCAP(ep.addr, ep.creds, options);
        this._tlscapClient = new _caProto.TLSCAP(ep.addr, ep.creds, options);
        this._cryptoPrimitives = new CryptoSuite();
    },

    /**
     * Get the security level
     * @returns The security level
     */
    getSecurityLevel: function() {
        return this._cryptoPrimitives.getSecurityLevel();
    },

    /**
     * Set the security level
     * @params securityLevel The security level
     */
    setSecurityLevel: function(securityLevel) {
        this._cryptoPrimitives.setSecurityLevel(securityLevel);
    },

    /**
     * Get the hash algorithm
     * @returns {string} The hash algorithm
     */
    getHashAlgorithm: function() {
        return this._cryptoPrimitives.getHashAlgorithm();
    },

    /**
     * Set the hash algorithm
     * @params hashAlgorithm The hash algorithm ('SHA2' or 'SHA3')
     */
    setHashAlgorithm: function(hashAlgorithm) {
        this._cryptoPrimitives.setHashAlgorithm(hashAlgorithm);
    },

    getCrypto: function() {
        return this._cryptoPrimitives;
    },

    /**
     * Register the member and return an enrollment secret.
     * @param req Registration request with the following fields: name, role
     * @param registrar The identity of the registrar (i.e. who is performing the registration)
     * @returns Promise for the enrollmentSecret
     */
    register: function(req, registrar /*Member*/) {
        return new Promise(function(resolve, reject) {
            if (!req.enrollmentID) {
                reject(new Error("missing req.enrollmentID"));
            }

            if (!registrar) {
                reject(new Error("chain registrar is not set"));
            }

            var protoReq = new _caProto.RegisterUserReq();
            protoReq.setId({id:req.enrollmentID});
            protoReq.setRole(rolesToMask(req.roles));
            protoReq.setAffiliation(req.affiliation);

            // Create registrar info
            var protoRegistrar = new _caProto.Registrar();
            protoRegistrar.setId({id:registrar.getName()});
            if (req.registrar) {
                if (req.registrar.roles) {
                   protoRegistrar.setRoles(req.registrar.roles);
                }
                if (req.registrar.delegateRoles) {
                   protoRegistrar.setDelegateRoles(req.registrar.delegateRoles);
                }
            }

            protoReq.setRegistrar(protoRegistrar);

            // Sign the registration request
            var buf = protoReq.toBuffer();
            var signKey = this._cryptoPrimitives.ecdsaKeyFromPrivate(registrar.getEnrollment().key, 'hex');
            var sig = this._cryptoPrimitives.ecdsaSign(signKey, buf);
            protoReq.setSig( new _caProto.Signature(
                {
                    type: _caProto.CryptoType.ECDSA,
                    r: new Buffer(sig.r.toString()),
                    s: new Buffer(sig.s.toString())
                }
            ));

            // Send the registration request
            this._ecaaClient.registerUser(protoReq, function (err, token) {
                if (err) {
                    reject(err);
                } else {
                    resolve(token ? token.tok.toString() : null);
                }
            });
        });
    },

    /**
     * Enroll the member and return an opaque member object
     * @param req Enrollment request with the following fields: name, enrollmentSecret
     * @returns Promise for {key,cert,chainKey}
     */
    enroll: function(req) {
        var self = this;

        return new Promise(function(resolve, reject) {
            if (!req.enrollmentID) {
                reject(new Error("req.enrollmentID is not set"));
            }

            if (!req.enrollmentSecret) {
                reject(new Error("req.enrollmentSecret is not set"));
            }

            // generate ECDSA keys: signing and encryption keys
            // 1) signing key
            var signingKeyPair = self._cryptoPrimitives.ecdsaKeyGen();
            var spki = new asn1.x509.SubjectPublicKeyInfo(signingKeyPair.pubKeyObj);
            // 2) encryption key
            var encryptionKeyPair = self.cryptoPrimitives.ecdsaKeyGen();
            var spki2 = new asn1.x509.SubjectPublicKeyInfo(encryptionKeyPair.pubKeyObj);

            // create the proto message
            var eCertCreateRequest = new _caProto.ECertCreateReq();
            var timestamp = utils.GenerateTimestamp();
            eCertCreateRequest.setTs(timestamp);
            eCertCreateRequest.setId({id: req.enrollmentID});
            eCertCreateRequest.setTok({tok: new Buffer(req.enrollmentSecret)});

            // public signing key (ecdsa)
            var signPubKey = new _caProto.PublicKey(
                {
                    type: _caProto.CryptoType.ECDSA,
                    key: new Buffer(spki.getASN1Object().getEncodedHex(), 'hex')
                });
            eCertCreateRequest.setSign(signPubKey);

            // public encryption key (ecdsa)
            var encPubKey = new _caProto.PublicKey(
                {
                    type: _caProto.CryptoType.ECDSA,
                    key: new Buffer(spki2.getASN1Object().getEncodedHex(), 'hex')
                });
            eCertCreateRequest.setEnc(encPubKey);

            self._ecapClient.createCertificatePair(eCertCreateRequest, function (err, eCertCreateResp) {
                if (err) {
                    reject(err);
                }

                var cipherText = eCertCreateResp.tok.tok;
                var decryptedTokBytes = self._cryptoPrimitives.eciesDecrypt(encryptionKeyPair.prvKeyObj, cipherText);

                //debug(decryptedTokBytes);
                // debug(decryptedTokBytes.toString());
                // debug('decryptedTokBytes [%s]', decryptedTokBytes.toString());
                eCertCreateRequest.setTok({tok: decryptedTokBytes});
                eCertCreateRequest.setSig(null);

                var buf = eCertCreateRequest.toBuffer();

                var signKey = self._cryptoPrimitives.ecdsaKeyFromPrivate(signingKeyPair.prvKeyObj.prvKeyHex, 'hex');
                //debug(new Buffer(sha3_384(buf),'hex'));
                var sig = self._cryptoPrimitives.ecdsaSign(signKey, buf);

                eCertCreateRequest.setSig(new _caProto.Signature(
                    {
                        type: _caProto.CryptoType.ECDSA,
                        r: new Buffer(sig.r.toString()),
                        s: new Buffer(sig.s.toString())
                    }
                ));
                self._ecapClient.createCertificatePair(eCertCreateRequest, function (err, eCertCreateResp) {
                    if (err) {
                        reject(err);
                    }

                    var enrollment = {
                        key: signingKeyPair.prvKeyObj.prvKeyHex,
                        cert: eCertCreateResp.certs.sign.toString('hex'),
                        chainKey: eCertCreateResp.pkchain.toString('hex')
                    };
                    // debug('cert:\n\n',enrollment.cert)
                    resolve(enrollment);
                });
            });
        });
    },

    /**
     * Get an array of transaction certificates (tcerts).
     * @param {Object} req Request of the form: {name,enrollment,num} where
     * 'name' is the member name,
     * 'enrollment' is what was returned by enroll, and
     * 'num' is the number of transaction contexts to obtain.
     * @returns Promise for an array of TCerts
     */
    getTCertBatch: function(req) {
        var self = this;

        var timestamp = utils.GenerateTimestamp();

        return new Promise(function(resolve, reject) {
            // create the proto
            var tCertCreateSetReq = new _caProto.TCertCreateSetReq();
            tCertCreateSetReq.setTs(timestamp);
            tCertCreateSetReq.setId({id: req.name});
            tCertCreateSetReq.setNum(req.num);
            if (req.attrs) {
                var attrs = [];
                for (var i = 0; i < req.attrs.length; i++) {
                    attrs.push({attributeName:req.attrs[i]});
                }
                tCertCreateSetReq.setAttributes(attrs);
            }

            // serialize proto
            var buf = tCertCreateSetReq.toBuffer();

            // sign the transaction using enrollment key
            var signKey = self._cryptoPrimitives.ecdsaKeyFromPrivate(req.enrollment.key, 'hex');
            var sig = self._cryptoPrimitives.ecdsaSign(signKey, buf);

            tCertCreateSetReq.setSig(new _caProto.Signature(
                {
                    type: _caProto.CryptoType.ECDSA,
                    r: new Buffer(sig.r.toString()),
                    s: new Buffer(sig.s.toString())
                }
            ));

            // send the request
            self._tcapClient.createCertificateSet(tCertCreateSetReq, function (err, resp) {
                if (err) {
                    reject(err);
                }
                // debug('tCertCreateSetResp:\n', resp);
                resolve(self._processTCertBatch(req, resp));
            });
        });
    },

    /**
     * Process a batch of tcerts after having retrieved them from the TCA.
     */
    _processTCertBatch: function(req, resp) {
        //
        // Derive secret keys for TCerts
        //

        var enrollKey = req.enrollment.key;
        var tCertOwnerKDFKey = resp.certs.key;
        var tCerts = resp.certs.certs;

        var byte1 = new Buffer(1);
        byte1.writeUInt8(0x1, 0);
        var byte2 = new Buffer(1);
        byte2.writeUInt8(0x2, 0);

        var tCertOwnerEncryptKey = this._cryptoPrimitives.hmac(tCertOwnerKDFKey, byte1).slice(0, 32);
        var expansionKey = this._cryptoPrimitives.hmac(tCertOwnerKDFKey, byte2);

        var tCertBatch = [];

        // Loop through certs and extract private keys
        for (var i = 0; i < tCerts.length; i++) {
            var tCert = tCerts[i];
            var x509Certificate;
            try {
                x509Certificate = new X509Certificate(tCert.cert);
            } catch (ex) {
                continue
            }

            // debug("HERE2: got x509 cert");
            // extract the encrypted bytes from extension attribute
            var tCertIndexCT = x509Certificate.criticalExtension(crypto.TCertEncTCertIndex);
            // debug('tCertIndexCT: ',JSON.stringify(tCertIndexCT));
            var tCertIndex = this._cryptoPrimitives.aesCBCPKCS7Decrypt(tCertOwnerEncryptKey, tCertIndexCT);
            // debug('tCertIndex: ',JSON.stringify(tCertIndex));

            var expansionValue = this._cryptoPrimitives.hmac(expansionKey, tCertIndex);
            // debug('expansionValue: ',expansionValue);

            // compute the private key
            var one = new BN(1);
            var k = new BN(expansionValue);
            var n = this._cryptoPrimitives.ecdsaKeyFromPrivate(enrollKey, 'hex').ec.curve.n.sub(one);
            k = k.mod(n).add(one);

            var D = this._cryptoPrimitives.ecdsaKeyFromPrivate(enrollKey, 'hex').getPrivate().add(k);
            var pubHex = this._cryptoPrimitives.ecdsaKeyFromPrivate(enrollKey, 'hex').getPublic('hex');
            D = D.mod(this._cryptoPrimitives.ecdsaKeyFromPublic(pubHex, 'hex').ec.curve.n);

            // Put private and public key in returned tcert
            var tcert = new TCert(tCert.cert, this._cryptoPrimitives.ecdsaKeyFromPrivate(D, 'hex'));
            tCertBatch.push(tcert);
        }

        if (tCertBatch.length == 0) {
            throw Error('Failed fetching TCertBatch. No valid TCert received.')
        }

        return tCertBatch;

    }

});

module.exports = MemberServices;


