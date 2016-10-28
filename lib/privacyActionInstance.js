/*jslint node: true, vars: true */

//
// Contruct a Privacy Action Instance from a combination of the Privacy Action
// and Privacy Action instance
//

/*

A Privacy Action Instance is created from a Privacy Action at Privacy Pipe creation time.
It contains the fixed and runtime metadata to obfuscate or de-obfuscate data. This covers specific instance of a Key Management Service,
the Obfuscation service, and any encrypt key metadata that is generated through the encrypt process so it can be used for decryption.

It has a globally unique @id that is record in any values that are obfuscated by it in their Etype field.

*/

const assert = require('assert');
const jsonldUtils = require('jsonld-utils/lib/jldUtils');
const moment = require('moment');
const PNDataModel = require('data-models/lib/PNDataModel');
const PN_P = PNDataModel.PROPERTY;
const PN_T = PNDataModel.TYPE;
const util = require('util');

var model = {};
model.utils = {};

//
// Create a Privacy Action Instance from the passed in params
//
// *pait - the privacy action instance template passed in the privacy pipe
// *paction - the privacy action
// props
model.utils.create = function create(pait, paction, pp, props) {
  'use strict';
  assert(pait, 'pait param is missing');
  assert(paction, 'paction param is missing');
  assert(pp, 'pp param is missing');
  assert(props.hostname, util.format('props.hostname missing - required to create ids:%j', props));
  assert(props.domainName, util.format('props.domainName missing - required to create ids:%j', props));

  let node = {};

  if (!(jsonldUtils.isType(pait, PN_T.PrivacyActionInstance))) {
    return PNDataModel.errors.createTypeError({
      id: PNDataModel.ids.createErrorId(props.hostname, moment().unix()),
      errMsg: util.format('ERROR type is not [%s] missing in:%j', PN_T.PrivacyActionInstance, pait),
    });
  }

  node['@id'] = pait['@id'];
  node['@type'] = [PN_T.Metadata, PN_T.PrivacyActionInstance];

  // copy constant values that cannot be overridden
  node[PN_P.privacyAction] = paction['@id'];
  node[PN_P.contentObfuscationAlgorithm] = paction[PN_P.contentObfuscationAlgorithm];
  node[PN_P.obfuscationProvider] = paction[PN_P.obfuscationProvider];
  node[PN_P.kms] = paction[PN_P.kms];

  // copy variable values that are only passed at runtime
  node[PN_P.privacyPipe] = pp['@id'];
  node[PN_P.action] = pait[PN_P.action];

  if (pait[PN_P.encryptKeyMD]) {
    node[PN_P.encryptKeyMD] = pait[PN_P.encryptKeyMD];
  }

  if (pait[PN_P.encryptKeyMDJWT]) {
    node[PN_P.encryptKeyMDJWT] = pait[PN_P.encryptKeyMDJWT];
  }

  // If the obfuscation service is in the action it should not be passed in
  // as cannot be overridden
  if (paction[PN_P.obfuscationService]) {
    if (pait[PN_P.obfuscationService]) {
      return PNDataModel.errors.createTypeError({
        id: PNDataModel.ids.createErrorId(props.hostname, moment().unix()),
        errMsg: util.format('ERROR privacy action has a obfuscation service cannot override. Action%j Instance:%j', paction, pait),
      });
    } else {
      node[PN_P.obfuscationService] = paction[PN_P.obfuscationService];
    }
  } else {
    node[PN_P.obfuscationService] = pait[PN_P.obfuscationService];
  }

  // make sure have an onfuscation service
  if (!node[PN_P.obfuscationService]) {
    return PNDataModel.errors.createTypeError({
      id: PNDataModel.ids.createErrorId(props.hostname, moment().unix()),
      errMsg: util.format('ERROR no obfuscation service in action or instance. Action%j Instance:%j', paction, pait),
    });
  }

  // copy values that can be override in the template
  if (pait[PN_P.skipOrchestration]) {
    node[PN_P.skipOrchestration] = pait[PN_P.skipOrchestration];
  } else {
    node[PN_P.skipOrchestration] = paction[PN_P.skipOrchestration];
  }

  //
  // If skip orchestration is false, make sure there is schema
  //
  if (!node[PN_P.skipOrchestration]) {

    // If the schema is in the action it should not be passed in
    // as cannot be overridden
    if (paction[PN_P.schema]) {
      if (pait[PN_P.schema]) {
        return PNDataModel.errors.createTypeError({
          id: PNDataModel.ids.createErrorId(props.hostname, moment().unix()),
          errMsg: util.format('ERROR privacy action has a schema cannot override. Action%j Instance:%j', paction, pait),
        });
      } else {
        node[PN_P.schema] = paction[PN_P.schema];
      }
    } else {
      node[PN_P.schema] = pait[PN_P.schema];
    }

    // make sure have a schema as not skipping
    if (!node[PN_P.schema]) {
      return PNDataModel.errors.createTypeError({
        id: PNDataModel.ids.createErrorId(props.hostname, moment().unix()),
        errMsg: util.format('ERROR no schema in action or instance. Action%j Instance:%j', paction, pait),
      });
    }
  }

  return node;
};

//
// convert a YAML node into a Privacy Action Instance JSON-LD node.
// NOTE THIS IS JUST A TEMPLATE not the fully created version
// only pass in what can be overridden
//  - id
//  - privacy_action: the id
//  - skipOrchestration
//  - obfuscation_service
//  - schema
//  - encrypt_key_md_jwt
//
// *yaml - the JSON version of the yaml node
// *props - var props
//
model.utils.YAML2Node = function YAML2Node(yaml, props) {
  'use strict';
  assert(yaml, 'yaml param is missing');
  assert(props, 'props param is missing');
  assert(props.hostname, util.format('props.hostname missing - required to create ids:%j', props));
  assert(props.domainName, util.format('props.domainName missing - required to create ids:%j', props));

  let node = {};

  if (!yaml.id) {
    return PNDataModel.errors.createTypeError({
      id: PNDataModel.ids.createErrorId(props.hostname, moment().unix()),
      errMsg: util.format('ERROR id missing from YAML privacy action format:%j', yaml),
    });
  } else {
    node['@id'] = PNDataModel.ids.createPrivacyActionInstanceId(props.domainName, yaml.id);
  }

  node['@type'] = [PN_T.PrivacyActionInstance];

  if (yaml.privacy_action) {
    node[PN_P.privacyAction] = yaml.privacy_action;
  }

  // lol can set to false or true so need to check for undefined
  if (typeof yaml.skip_orchestration !== 'undefined') {
    node[PN_P.skipOrchestration] = yaml.skip_orchestration;
  }

  if (yaml.schema) {
    node[PN_P.schema] = yaml.schema;
  }

  if (yaml.encrypy_key_md_jwt) {
    node[PN_P.encryptKeyMDJWT] = yaml.encrypy_key_md_jwt;
  }

  // verify the node is valid
  let error = model.utils.verifyTemplate(node, props);
  if (error) {
    return error;
  } else {
    return node;
  }
};

// ONLY VERFIY TEMPLATE properties that must be there
model.utils.verifyTemplate = function verifyTemplate(node, props) {
  'use strict';
  assert(node, 'node param missing');
  assert(props, 'props param is missing');
  assert(props.hostname, 'props.hostname is missing');

  let hostname = props.hostname;

  if (!node['@id']) {
    return PNDataModel.errors.createTypeError({
      id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
      errMsg: util.format('ERROR @id missing from:%j', node),
    });
  }

  if (!jsonldUtils.isType(node, PN_T.PrivacyActionInstance)) {
    return PNDataModel.errors.createTypeError({
      id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
      errMsg: util.format('ERROR type is not [%s] missing in:%j', PN_T.PrivacyActionInstance, node),
    });
  }

  if (!node[PN_P.privacyAction]) {
    return PNDataModel.errors.createTypeError({
      id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
      errMsg: util.format('ERROR %s missing from:%j', PN_P.privacyAction, node),
    });
  }

  // all ok :)
  return null;
};

module.exports = {
  utils:        model.utils,
};
