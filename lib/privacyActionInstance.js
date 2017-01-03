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

It has the following properties:
•	@id: http://md.pn.id.webshield.io/ipa/<domain name reversed>#some value
•	@type: [pn_t.PrivacyActionInstance, pn_t.Metadata]
•	pn_p.privacy_pipe: the @id of the pipe that was involved
•	pn_p.privacy_action: the @id of the privacy action that was involved
•	pn_p.action: obfuscate or deobfuscate action.
•	pn_p.privacy_action_instance_2_deobfuscate: used for deobfuscation and holds the @id of the privacy action that was used to obfuscate the data.
•	pn_p.skip_orchestration: (optional) overrides value in privacy Action
•	pn_p.obfuscation_provider: copied from privacy action
•	pn_p.content_obfuscation_algorithm: copied from privacy action
•	pn_p.obfuscation_provider: copied from privacy action
•	pn_p.obfuscation_service: If specified in the privacy action then copied from it,
   if not must be specified at pipe creation time. Note cannot override if specified at action level.
•	pn_p.kms: copied from privacy action.
•	pn_p.schema: copied from privacy action or passed in at pipe creation time.
•	pn_p.content_encrypt_key_md:  If specified in the privacy action then copied from it, if not must be specified at pipe creation time. Note cannot override if specified at action level.
•	pn_p.key_encrypt_key_md:  If specified in the privacy action then copied from it, if not must be specified at pipe creation time. Note cannot override if specified at action level.
- pn_p.privacyActionInstance2Deobfuscate - if deobfuscating then need to understand what OV should be de-obfuscating as there @type will be the pai
  that obfuscated them, not this one. Hence add the @id of the pai that obfuscated them so can find it.

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

  // If key encryption key md is in action it cannot be overriden at the instance level
  if (paction[PN_P.keyEncryptKeyMD]) {
    if (pait[PN_P.keyEncryptKeyMD]) {
      return PNDataModel.errors.createTypeError({
        id: PNDataModel.ids.createErrorId(props.hostname, moment().unix()),
        errMsg: util.format('ERROR privacy action has a key encrypt key metadata cannot override. Action%j Instance:%j', paction, pait),
      });
    } else {
      node[PN_P.keyEncryptKeyMD] = paction[PN_P.keyEncryptKeyMD];
    }
  } else if (pait[PN_P.keyEncryptKeyMD]) {
    node[PN_P.keyEncryptKeyMD] = pait[PN_P.keyEncryptKeyMD];
  }

  // If content encryption key md is in action it cannot be overriden at the instance level
  if (paction[PN_P.contentEncryptKeyMD]) {
    if (pait[PN_P.contentEncryptKeyMD]) {
      return PNDataModel.errors.createTypeError({
        id: PNDataModel.ids.createErrorId(props.hostname, moment().unix()),
        errMsg: util.format('ERROR privacy action has a content encrypt key metadata cannot override. Action%j Instance:%j', paction, pait),
      });
    } else {
      node[PN_P.contentEncryptKeyMD] = paction[PN_P.contentEncryptKeyMD];
    }
  } else if (pait[PN_P.contentEncryptKeyMD]) {
    node[PN_P.contentEncryptKeyMD] = pait[PN_P.contentEncryptKeyMD];
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
  } else if (pait[PN_P.obfuscationService]) {
    node[PN_P.obfuscationService] = pait[PN_P.obfuscationService];
  }

  // make sure have an obfuscation service
  // FIXME UNTIL ADD OBFUSCATION SERVICE COMMENT OUT
  /*if (!node[PN_P.obfuscationService]) {
    return PNDataModel.errors.createTypeError({
      id: PNDataModel.ids.createErrorId(props.hostname, moment().unix()),
      errMsg: util.format('ERROR no obfuscation service in action or instance. Action%j Instance:%j', paction, pait),
    });
  }*/

  // when create a template can specify the action that obfuscated the value and
  // hence want to de-obfuscate
  if (pait[PN_P.privacyActionInstance2Deobfuscate]) {
    node[PN_P.privacyActionInstance2Deobfuscate] = pait[PN_P.privacyActionInstance2Deobfuscate];
  }

  // when create a template can specify the pipe that obfuscated the value and
  // hence want to de-obfuscate // NOT USED ?? just use PAI?
  if (pait[PN_P.privacyPipe2Deobfuscate]) {
    node[PN_P.privacyPipe2Deobfuscate] = pait[PN_P.privacyPipe2Deobfuscate];
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
//  - action
//  - schema
//  - encrypt_key_md
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

  if (yaml.obfuscation_service) {
    node[PN_P.obfuscationService] = yaml.obfuscation_service;
  }

  if (yaml.privacy_action_instance_2_deobfuscate) {
    node[PN_P.privacyActionInstance2Deobfuscate] = yaml.privacy_action_instance_2_deobfuscate;
  }

  if (yaml.privacy_pipe_2_deobfuscate) {
    node[PN_P.privacyPipe2Deobfuscate] = yaml.privacy_pipe_2_deobfuscate;
  }

  if (yaml.action) {
    if (yaml.action.toLowerCase() === 'obfuscate') {
      node[PN_P.action] = PN_T.Obfuscate;
    } else if (yaml.action.toLowerCase() === 'deobfuscate') {
      node[PN_P.action] = PN_T.Deobfuscate;
    }
  }

  if (yaml.schema) {
    // this must be string, as it may not be JSONLD compliant and have
    // non URL props, so any expand operation would remove.
    // Check if a string if so then leave otherwise stringify
    if (typeof yaml.schema === 'string') {
      node[PN_P.schema] = yaml.schema;
    } else {
      node[PN_P.schema] = JSON.stringify(yaml.schema);
    }
  }

  if (yaml.key_encrypt_key_md) {
    node[PN_P.keyEncryptKeyMD] = yaml.key_encrypt_key_md;
  }

  if (yaml.content_encrypt_key_md) {
    node[PN_P.contentEncryptKeyMD] = yaml.content_encrypt_key_md;
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

  if ((node[PN_P.action] !== PN_T.Obfuscate) && (node[PN_P.action] !== PN_T.Deobfuscate)) {
    return PNDataModel.errors.createTypeError({
      id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
      errMsg: util.format('ERROR %s is not obfuscate or deobfuscate :%j', PN_P.action, node),
    });
  }

  if (node[PN_P.action] === PN_T.Obfuscate) {

    // a de-obfuscate template does not have this set as determined from the instance
    // that want to de-obfuscate. But an obfuscate node needs
    if (!node[PN_P.privacyAction]) {
      return PNDataModel.errors.createTypeError({
        id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
        errMsg: util.format('ERROR %s missing from:%j', PN_P.privacyAction, node),
      });
    }

    // should not be set for an obfuscate node
    if (node[PN_P.privacyActionInstance2Deobfuscate]) {
      return PNDataModel.errors.createTypeError({
        id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
        errMsg: util.format('ERROR obfuscate should not have %s node:%j', PN_P.privacyActionInstance2Deobfuscate, node),
      });
    }

    // should not be set for an obfuscate node
    if (node[PN_P.privacyPipe2Deobfuscate]) {
      return PNDataModel.errors.createTypeError({
        id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
        errMsg: util.format('ERROR obfuscate should not have %s node:%j', PN_P.privacyPipe2Deobfuscate, node),
      });
    }
  }

  if (node[PN_P.action] === PN_T.Deobfuscate) {

    // should be set for a deobfuscate node
    if (!node[PN_P.privacyActionInstance2Deobfuscate]) {
      return PNDataModel.errors.createTypeError({
        id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
        errMsg: util.format('ERROR deobfuscate should have %s node:%j', PN_P.privacyActionInstance2Deobfuscate, node),
      });
    }

    // FOR NOW THIS MUST BE SUPPLIED IN FUTURE MAKE OPTIONAL should not be set for an obfuscate node
    if (!node[PN_P.privacyPipe2Deobfuscate]) {
      return PNDataModel.errors.createTypeError({
        id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
        errMsg: util.format('ERROR deobfuscate should have %s node:%j', PN_P.privacyPipe2Deobfuscate, node),
      });
    }
  }

  // all ok :)
  return null;
};

module.exports = {
  utils:        model.utils,
};
