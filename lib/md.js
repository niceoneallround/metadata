/*jslint node: true, vars: true */

/*

All Metadata provides the following functions
 *YAML2Node -  convert a YAML node into a JSON-LD node and verify
 *verify - verify that the JSON-LD representation is correct
 *JWTPayload2Node - take a JWT payload and return a JSON-LD node
    - handles either a pn_graph or a metadata claim

The class contains high level dispatchers for the above and switches to
correct conrete one based on type

*/

const assert = require('assert');
const ISAUtils = require('./ISAlgorithm').utils;
const jsonldUtils = require('jsonld-utils/lib/jldUtils');
const JWTClaims = require('jwt-utils/lib/jwtUtils').claims;
const moment = require('moment');
const PNDataModel = require('data-models/lib/PNDataModel');
const PN_P = PNDataModel.PROPERTY;
const PN_T = PNDataModel.TYPE;
const PrivacyAlgorithmUtils = require('./privacyAlgorithm').utils;
const PrivacyAlgorithmV2Utils = require('./privacyAlgorithmV2').utils;
const PPUtils = require('./privacyPipe').utils;
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
    switch (yaml.type.toLowerCase()) {

      case 'identitysyndicationalgorithm': {
        return ISAUtils.YAML2Node(yaml, props);
      }

      case 'privacyalgorithm': {
        return PrivacyAlgorithmUtils.YAML2Node(yaml, props);
      }

      case 'privacyalgorithmv2': {
        return PrivacyAlgorithmV2Utils.YAML2Node(yaml, props);
      }

      case 'privacypipe': {
        return PPUtils.YAML2Node(yaml, props);
      }

      case 'referencesource': {
        return RSUtils.YAML2Node(yaml, props);
      }

      default: {
        return PNDataModel.errors.createTypeError({
          id: PNDataModel.ids.createErrorId(props.hostname, moment().unix()),
          errMsg: util.format('ERROR YAML2Node unknown type missing from YAML format cannot dispatch:%j', yaml),
        });
      }
    } // switch
  }
};

//
// Generate a complete ID for the yaml node
//
model.utils.YAML2Id = function YAML2Id(yaml, props) {
  'use strict';
  assert(yaml, 'yaml param is missing');
  assert(props, 'props param is missing');
  assert(props.domainName, util.format('props.domainName missing - required to create ids:%j', props));

  if (!yaml.type) {
    return PNDataModel.errors.createTypeError({
      id: PNDataModel.ids.createErrorId(props.hostname, moment().unix()),
      errMsg: util.format('ERROR type missing from YAML format cannot dispatch:%j', yaml),
    });
  } else {
    switch (yaml.type.toLowerCase()) {
      case 'identitysyndicationalgorithm':
      case 'privacyalgorithm':
      case 'privacyalgorithmv2':
      case 'referencesource': {
        return PNDataModel.ids.createResourceId(props.domainName, yaml.id);
      }

      case 'privacypipe': {
        return PNDataModel.ids.createPrivacyPipeId(props.domainName, yaml.id);
      }

      default: {
        return PNDataModel.errors.createTypeError({
          id: PNDataModel.ids.createErrorId(props.hostname, moment().unix()),
          errMsg: util.format('ERROR YAML2Id unknown type missing from YAML format cannot dispatch:%j', yaml),
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

  if (jsonldUtils.isType(node, PN_T.IdentitySyndicationAlgorithm)) {
    return ISAUtils.verify(node, props.hostname);
  } else if (jsonldUtils.isType(node, PN_T.PrivacyAlgorithm)) {
    if (node[PN_P.version]) { // only version 2 has a version
      return PrivacyAlgorithmV2Utils.verify(node, props);
    } else {
      return PrivacyAlgorithmUtils.verify(node, props.hostname);
    }
  } else if (jsonldUtils.isType(node, PN_T.PrivacyPipe)) {
    if (node[PN_P.version]) { // only version 2 has a version
      return PPUtils.verify(node, props);
    } else {
      return node;
    }
  } else if (jsonldUtils.isType(node, PN_T.ReferenceSource)) {
    return RSUtils.verify(node, props.hostname);
  } else {
    return PNDataModel.errors.createTypeError({
      id: PNDataModel.ids.createErrorId(props.hostname, moment().unix()),
      errMsg: util.format('ERROR VERIFY unknown @type cannot dispatch:%j', node),
    });
  }
};

//-------------------------------------
// Convert a JWT Payload into a JSON-LD node - and verify correct
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

    // Validate that JWT payload standard claims that are requird, sub iss, iat.
    if (!payload.sub) {
      return PNDataModel.errors.createTypeError({
        id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
        errMsg: util.format('ERROR JWT payload does not contains a subject:%j', payload),
      });
    }

    // must have a subject claim
    if (!payload.sub) {
      return PNDataModel.errors.createTypeError({
        id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
        errMsg: util.format('ERROR %s missing from JWT payload:%j', 'sub', payload),
      });
    }

    // must have an issuer claim
    if (!payload.iss) {
      return PNDataModel.errors.createTypeError({
        id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
        errMsg: util.format('ERROR %s missing from JWT payload:%j', 'iss', payload),
      });
    }

    md = payload[JWTClaims.METADATA_CLAIM];
    md['@id'] = payload.sub;
    md[PN_P.issuer] = PNDataModel.utils.createCNameValue(payload.iss);
    md[PN_P.creationTime] = moment(payload.iat).toJSON();

    //
    // Verify that the metadata is valid
    //
    let error = model.utils.verify(md, { hostname: hostname });
    if (error) {
      return error;
    } else {
      return md;
    }
  } else if (payload[JWTClaims.PN_GRAPH_CLAIM]) {
    //
    // Just return the node
    //
    let md = payload[JWTClaims.PN_GRAPH_CLAIM];

    // if the metadata node does not have an issuer add from the JWT
    if (!md[PN_P.issuer]) {
      md[PN_P.issuer] = PNDataModel.utils.createCNameValue(payload.iss);
    }

    // if the metadata node does not have a creation Time add from the JWT
    if (!md[PN_P.creationTime]) {
      md[PN_P.creationTime] =  moment(payload.iat).toJSON();
    }

    let error = model.utils.verify(md, { hostname: hostname });
    if (error) {
      return error;
    } else {
      return md;
    }
  } else {
    //
    // Error unknown metadata JWT
    //
    return PNDataModel.errors.createTypeError({
      id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
      errMsg: util.format('ERROR JWTPayload2Node no known metadata claim in JWT cannot dispatch:%j', payload),
    });
  }

};

module.exports = {
  utils:        model.utils,
};
