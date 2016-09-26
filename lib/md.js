/*jslint node: true, vars: true */

//
// Contains dispatchers for constructors and verifiers
// *YAML2Node - convert a YAML node into a JSON-LD node and verify
// *verify - verify JSON-LD node
// *JWTPayload2Node - take a JWT payload and return a JSON-LD node
//     - handles either a pn_graph or a metadata claim

const assert = require('assert');
const jsonldUtils = require('jsonld-utils/lib/jldUtils');
const JWTClaims = require('jwt-utils/lib/jwtUtils').claims;
const moment = require('moment');
const PNDataModel = require('data-models/lib/PNDataModel');
const PN_P = PNDataModel.PROPERTY;
const PN_T = PNDataModel.TYPE;
const PrivacyAlgorithmUtils = require('./privacyAlgorithm').utils;
const RSUtils = require('./referenceSource').utils;
const util = require('util');

var model = {};
model.utils = {};

//--------------------------------
// Constructors from YAML nodes
//--------------------------------

model.utils.YAML2Node = function YAML2Node(yaml, props) {
  'use strict';
  assert(yaml, 'yaml param is missing');
  assert(props, 'props param is missing');
  assert(props.hostname, util.format('props.hostname missing - required to create ids:%j', props));

  if (!yaml.type) {
    return PNDataModel.errors.createTypeError({
      id: PNDataModel.ids.createErrorId(props.hostname, moment().unix()),
      errMsg: util.format('ERROR type missing from YAML format cannot dispatch:%j', yaml),
    });
  } else {
    switch (yaml.type) {
      case 'PrivacyAlgorithm': {
        return PrivacyAlgorithmUtils.YAML2Node(yaml, props);
      }

      case 'ReferenceSource': {
        return RSUtils.YAML2Node(yaml, props);
      }

      default: {
        return PNDataModel.errors.createTypeError({
          id: PNDataModel.ids.createErrorId(props.hostname, moment().unix()),
          errMsg: util.format('ERROR unknown type missing from YAML format cannot dispatch:%j', yaml),
        });
      }
    } // switch
  }
};

//--------------------------------
// Verifiers for JSON-LD nodes
//--------------------------------

model.utils.verify = function verify(node, props) {
  'use strict';
  assert(node, 'node param is missing');
  assert(props, 'props param is missing');
  assert(props.hostname, util.format('props.hostname missing - required to create ids:%j', props));

  if (jsonldUtils.isType(node, PN_T.PrivacyAlgorithm)) {
    return PrivacyAlgorithmUtils.verify(node, props.hostname);
  } else if (jsonldUtils.isType(node, PN_T.ReferenceSource)) {
    return RSUtils.verify(node, props.hostname);
  } else {
    return PNDataModel.errors.createTypeError({
      id: PNDataModel.ids.createErrorId(props.hostname, moment().unix()),
      errMsg: util.format('ERROR unknown @type cannot dispatch:%j', node),
    });
  }
};

//-------------------------------------
// Convert a JWT Payload into a JSON-LD node - verifies correct
//---------------------------------------

//
// Handle the metadata being a METADATA_CLAIM or a PN_GRAPH_CLAIM
//
model.utils.JWTPayload2Node = function JWTPayload2Node(payload, hostname) {
  'use strict';
  assert(payload, 'payload param is missing');
  assert(hostname, 'hostname param is missing');

  let md = null;

  if (payload[JWTClaims.METADATA_CLAIM]) {
    if (!payload.sub) {
      return PNDataModel.errors.createTypeError({
        id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
        errMsg: util.format('ERROR payload does not contains a subject:%j', payload),
      });
    }

    md = payload[JWTClaims.METADATA_CLAIM];
    md['@id'] = payload.sub;
    md[PN_P.issuer] = PNDataModel.utils.createCNameValue(payload.iss);
    md[PN_P.creationTime] = moment(payload.iat).toJSON();
  } else if (payload[JWTClaims.PN_GRAPH_CLAIM]) {
    md = payload[JWTClaims.PN_GRAPH_CLAIM];
  } else {
    md = PNDataModel.errors.createTypeError({
      id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
      errMsg: util.format('ERROR no known metadata claim in JWT cannot dispatch:%j', payload),
    });
  }

  return md;
};

module.exports = {
  utils:        model.utils,
};
