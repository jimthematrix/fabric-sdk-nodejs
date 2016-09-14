var _asn1js = require("asn1js");
var common = require("asn1js/org/pkijs/common");
var _pkijs = require("pkijs");
var _x509schema = require("pkijs/org/pkijs/x509_schema");
var merge = require("node.extend");

/**
 * Abstract Syntax Notation One (ASN.1) is a standard and notation that describes 
 * rules and structures for representing, encoding, transmitting, and decoding data 
 * in telecommunications and computer networking
 *
 * 
 */
module.exports = function() {
  // #region Merging function/object declarations for ASN1js and PKIjs
  var asn1js = merge(true, _asn1js, common);
  var x509schema = merge(true, _x509schema, asn1js);
  var pkijs_1 = merge(true, _pkijs, asn1js);
  var pkijs = merge(true, pkijs_1, x509schema);

  return pkijs;
};