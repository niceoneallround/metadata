/*jslint node: true, vars: true */

//
// Contains constructors and verifiers for Privacy Action
//
// Implements
// * verify() - verifies a JSON-LD node
// * YAML2Node() - converts a YAML node to a JSON-LD node
//

/*

A Privacy Action meta-metadata that describes how to either obfuscate or de-obfuscate
JSON data using an obfuscation algorithm such as AES, SHA2, Tokenization, etc.

In this process it may uses a KMS and a Obfuscation Service

It is used to instaniate Privacy Action Instances at Privacy Pipe creation time

It is created at Privacy Algorithm create time, the JSON-LD node has the
following properties:
  @id:  https://md.pn.id.webshield.io/privacy_action/(hostname-reversed)#<value>
  @type: [pn_t.Metadata, pn_t.PrivacyAction]
  pn_p.description: test description
  pn_p.privacy_step: @id of owning step
  pn_p.content_obfuscation_algorithm: the fixed algorithm
  pn_p.obfuscation_provider: the fixed globally unique id of the provider.
     Need as there may not be an obfuscation service in the action and used to find one for the instance.
  pn_p.obfuscation_service: the @id of the obfuscation service
  pn_p.kms: the @id of the KMS service
  pn_p.skip_orhestration: If true indicates that the executor should not orchestrate
    the obfuscation using the schema, service and keys as this has already occurred externally.
    In this case the PN is really just passing the necessary metadata need to decrypt to the other side.
  pn_p.schema: [optional] A JSON Schema describing what properties should be acted on. If set fixed, others set at runtime

The Content Obfuscation Algorithm describes the algorithm that should be used on the content.
It may be any value as dependent on the PN clients but for interoperability it is recommended
using JSON Web Algorithm https://www.rfc-editor.org/rfc/rfc7518.txt,
or PN standard such as PN_T.Tokenization. Examples are A256GCM, SHA256

The Obfuscation Provider is a 3rd party service or 3rd party library that is providing the
Content Obfuscation Algorithm and enables other parties to determine what type of obfuscation
service is needed and if it is trust. They are represented by a globally unique @id such as
•	http://ionic-security.com
•	http//aws.amazon.com/kms
•	http://voltage.com
•	http://md.id.pn.webshield.io/obfuscation_provider/golang-crypto-local

The Privacy ActionYAML node has the following format

  - id: // the #value - builds the rest
    type: PrivacyAction
    description: // optional
    privacy_step:
    content_obfuscation_algorithm:
    obfuscation_provider:
    obfuscation_service:
    kms:
    skip_orhestration:
    schema:

The above is passed in a as JSON node
   { id: , type: , description:, etc}

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
// convert a YAML node into a Privacy Action JSON-LD node.
//
// *yaml - the JSON version of the yaml node
//
// optional props are
// props.issuer: add as issuer to the PA as is not part of YAML
// props.creationTime - add as creation time to the PA as not part of YAML
//
model.utils.YAML2Node = function YAML2Node(yaml, props) {
  'use strict';
  assert(yaml, 'yaml param is missing');
  assert(props, 'props param is missing');
  assert(props.hostname, util.format('props.hostname missing - required to create ids:%j', props));
  assert(props.domainName, util.format('props.domainName missing - required to create ids:%j', props));
  assert(props.pa, util.format('props.pa missing - required to verify:%j', props));

  let node = {};

  // check has id
  if (!yaml.id) {
    return PNDataModel.errors.createTypeError({
      id: PNDataModel.ids.createErrorId(props.hostname, moment().unix()),
      errMsg: util.format('ERROR id missing from YAML privacy action format:%j', yaml),
    });
  } else {
    node['@id'] = PNDataModel.ids.createPrivacyActionId(props.domainName, yaml.id);
  }

  if (yaml.description) {
    node[PN_P.description] = yaml.description;
  }

  if (yaml.content_obfuscation_algorithm) {
    node[PN_P.contentObfuscationAlgorithm] = yaml.content_obfuscation_algorithm;
  }

  if (yaml.obfuscation_provider) {
    node[PN_P.obfuscationProvider] = yaml.obfuscation_provider;
  }

  if (yaml.obfuscation_service) {
    node[PN_P.obfuscationService] = yaml.obfuscation_service;
  }

  if (yaml.kms) {
    node[PN_P.kms] = yaml.kms;
  }

  if (!yaml.skip_orchestration) {
    node[PN_P.skipOrchestration] = false;
  } else {
    node[PN_P.skipOrchestration] = yaml.skip_orchestration;
  }

  if (yaml.schema) {
    node[PN_P.schema] = yaml.schema;
  }

  if (!yaml.privacy_step) {
    if (!props.privacyStep) {
      return PNDataModel.errors.createTypeError({
        id: PNDataModel.ids.createErrorId(props.hostname, moment().unix()),
        errMsg: util.format('ERROR privacy_step missing from YAML privacy action format or props:%j', yaml),
      });
    } else {
      node[PN_P.privacyStep] = props.privacyStep;
    }
  } else {
    node[PN_P.privacyStep] = yaml.privacy_step;
  }

  if (yaml.type) {
    if (yaml.type.toLowerCase() !== 'privacyaction') {
      return PNDataModel.errors.createTypeError({
        id: PNDataModel.ids.createErrorId(props.hostname, moment().unix()),
        errMsg: util.format('ERROR type is not PrivacyAction:%j', yaml),
      });
    }
  }

  node['@type'] = [PN_T.Metadata, PN_T.PrivacyAction];

  // verify the node is valid
  let error = model.utils.verify(node, props);
  if (error) {
    return error;
  } else {
    return node;
  }
};

model.utils.verify = function verify(privacyAction, props) {
  'use strict';

  assert(privacyAction, 'node param missing');
  assert(props, 'props param is missing');
  assert(props.pa, util.format('props.pa is missing:%j', props));
  assert(props.hostname, util.format('props.hostname is missing:%j', props));

  let pa = props.pa;
  let hostname = props.hostname;

  if (!privacyAction['@id']) {
    return PNDataModel.errors.createTypeError({
      id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
      errMsg: util.format('ERROR @id missing from:%j', privacyAction),
    });
  }

  if (!(jsonldUtils.isType(privacyAction, PN_T.PrivacyAction))) {
    return PNDataModel.errors.createTypeError({
      id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
      errMsg: util.format('ERROR type is not [%s] missing in:%j in pa:%j', PN_T.PrivacyAction, privacyAction, pa),
    });
  }

  if (!privacyAction[PN_P.contentObfuscationAlgorithm]) {
    return PNDataModel.errors.createTypeError({
      id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
      errMsg: util.format('ERROR %s missing from:%j in pa:%j', PN_P.contentObfuscationAlgorithm, privacyAction, pa),
    });
  }

  if (!privacyAction[PN_P.obfuscationProvider]) {
    return PNDataModel.errors.createTypeError({
      id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
      errMsg: util.format('ERROR %s missing from:%j in pa:%j', PN_P.obfuscationProvider, privacyAction, pa),
    });
  }

  if (!privacyAction[PN_P.kms]) {
    return PNDataModel.errors.createTypeError({
      id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
      errMsg: util.format('ERROR %s missing from:%j in pa:%j', PN_P.kms, privacyAction, pa),
    });
  }

  if (!jsonldUtils.npUtils.getV(privacyAction, PN_P.skipOrchestration)) {
    //
    // If not skiping orchestration then must have a privacy schema
    //
    if (!privacyAction[PN_P.schema]) {
      return PNDataModel.errors.createTypeError({
        id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
        errMsg: util.format('ERROR %s missing from:%j in pa:%j', PN_P.schema, privacyAction, pa),
      });
    }
  }

  return null;
};

module.exports = {
  utils:        model.utils,
};
