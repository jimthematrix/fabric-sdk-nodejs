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

var util = require('util');
var Chain = require('./lib/Chain.js');
var utils = require('./lib/utils.js');

var _chains = {};

/**
 * Create a new chain.  If it already exists, throws an Error.
 * @param name {string} Name of the chain.  It can be any name and has value only for the client.
 * @returns
 */
module.exports.newChain = function(name) {
    var chain = _chains[name];
    
    if (chain) 
    	throw new Error(util.format("Chain %s already exists", name));

    chain = new Chain(name);

    _chains[name] = chain;
    return chain;
}

/**
 * Get a chain.  If it doesn't yet exist and 'create' is true, create it.
 * @param {string} chainName The name of the chain to get or create.
 * @param {boolean} create If the chain doesn't already exist, specifies whether to create it.
 * @return {Chain} Returns the chain, or null if it doesn't exist and create is false.
 */
module.exports.getChain = function(chainName, create) {
    var chain = _chains[chainName];

    if (!chain && create) {
        chain = newChain(chainName);
    }

    return chain;
}

module.exports.newKeyValueStore = function(path) {
	return utils.newKeyValueStore(path);
}