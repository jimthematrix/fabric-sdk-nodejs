var api = require('./api.js');
var utils = require('./utils.js');
var certPaser = require('./utils-x509cert.js');

var X509Certificate = api.X509Certificate.extend({

    _cert: null,

    constructor: function(buffer) {
        debug('cert:', JSON.stringify(buffer));
        // convert certBuffer to arraybuffer
        var certBuffer = utils.toArrayBuffer(buffer);
        // parse the DER-encoded buffer
        var asn1 = certPaser.org.pkijs.fromBER(certBuffer);
        this._cert = {};
        try {
            this._cert = new certPaser.org.pkijs.simpl.CERT({schema: asn1.result});
            debug('decoded certificate:\n', JSON.stringify(this._cert, null, 4));
        } catch (ex) {
            debug('error parsing certificate bytes: ', ex)
            throw ex;
        }
    },

    criticalExtension: function(oid) {
        var ext;
        debug('oid: ', oid);
        this._cert.extensions.some(function (extension) {
            debug('extnID: ', extension.extnID);
            if (extension.extnID === oid) {
                ext = extension;
                return true;
            }
        });
        debug('found extension: ', ext);
        debug('extValue: ', _toBuffer(ext.extnValue.value_block.value_hex));
        return _toBuffer(ext.extnValue.value_block.value_hex);
    }

});

// utility function to convert Javascript arraybuffer to Node buffers
function _toBuffer(ab) {
    var buffer = new Buffer(ab.byteLength);
    var view = new Uint8Array(ab);
    for (var i = 0; i < buffer.length; ++i) {
        buffer[i] = view[i];
    }
    return buffer;
}

module.exports = X509Certificate;
