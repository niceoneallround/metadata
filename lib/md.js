/*jslint node: true, vars: true */

//
// Contains dispatchers for constructors and verifiers
//

const assert = require('assert');
const jsonldUtils = require('jsonld-utils/lib/jldUtils');
const moment = require('moment');
const PNDataModel = require('data-models/lib/PNDataModel');
const PN_T = PNDataModel.TYPE;
const PrivacyAlgorithmUtils = require('./privacyAlgorithm').utils;
const util = require('util');

var model = {};
model.utils = {};

//--------------------------------
// Constructors from YAML nodes
//--------------------------------

model.utils.YAML2Metadata = function YAML2Metadata(yaml, props) {
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
      case 'PrivacyAlgorithm':
        return PrivacyAlgorithmUtils.YAML2PrivacyAlgorithm(yaml, props);
      default:
        return PNDataModel.errors.createTypeError({
          id: PNDataModel.ids.createErrorId(props.hostname, moment().unix()),
          errMsg: util.format('ERROR unknown type missing from YAML format cannot dispatch:%j', yaml),
        });
    } // switch
  }
};

//--------------------------------
// Verifiers from JSON-LD nodes
//--------------------------------

model.utils.verifyMetadata = function verifyMetadata(node, props) {
  'use strict';
  assert(node, 'node param is missing');
  assert(props, 'props param is missing');
  assert(props.hostname, util.format('props.hostname missing - required to create ids:%j', props));

  if (jsonldUtils.isType(node, PN_T.PrivacyAlgorithm)) {
    return PrivacyAlgorithmUtils.verifyPrivacyAlgorithm(node, props.hostname);
  } else {
    return PNDataModel.errors.createTypeError({
      id: PNDataModel.ids.createErrorId(props.hostname, moment().unix()),
      errMsg: util.format('ERROR unknown @type cannot dispatch:%j', node),
    });
  }
};

module.exports = {
  utils:        model.utils,
};
