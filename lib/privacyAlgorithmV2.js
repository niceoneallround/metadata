/*jslint node: true, vars: true */

//
// Contains constructors and verifiers for privacy algorithms, privacy steps
// and privacy actions.
//
// Implements
// * verify() - verifies a privacy algorithm JSON-LD node
// * YAML2Node() - converts a YAML node to a JSON-LD node
//

/*

A Privacy Algoritm is a PN Resource and meta-metadata that describes a multi-step,
distributed process for obfuscating PN Data Model Graphs at the field level.

It is used to instaniate Privacy Algoritm Instances at Privacy Pipe creation time.

It is created with a metadata claim inside a JWT. Once created cannot be changed.
 sub: globally unique id
    format: https://md.pn.id.webshield.io/resource/(hostname-reversed)#<value>
 iss: the issuer
 iat: the issue time
 pn_p.metadata - the claim with the JSON-LD node
   @type: [pn_t.Metadata, pn_t.PrivacyAlgorithm, pn_t.Resource]
   pn_p.privacy_step: [Privacy Step Nodes] - currently limited 1
   pn_p.description: test description
*/

const assert = require('assert');
const jsonldUtils = require('jsonld-utils/lib/jldUtils');
const moment = require('moment');
const PNDataModel = require('data-models/lib/PNDataModel');
const PStepUtils = require('./privacyStep').utils;
const PN_P = PNDataModel.PROPERTY;
const PN_T = PNDataModel.TYPE;
const util = require('util');

var model = {};
model.utils = {};

//
// convert a YAML node into a Privacy Algorithm JSON-LD node.
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
      errMsg: util.format('ERROR id missing from YAML privacy algorithm format:%j', yaml),
    });
  } else {
    node['@id'] = PNDataModel.ids.createPrivacyAlgorithmId(props.domainName, yaml.id);
  }

  node['@type'] = [PN_T.Metadata, PN_T.Resource, PN_T.PrivacyAlgorithm];
  node[PN_P.version] = '2';

  if (yaml.description) {
    node[PN_P.description] = yaml.description;
  }

  // note verify validates
  if ((props) && (props.issuer)) {
    node[PN_P.issuer] = props.issuer;
  }

  // note verify validates
  if ((props) && (props.creationTime)) {
    node[PN_P.creationTime] = props.creationTime;
  }

  // create the privacy steps
  props.pa = node;
  if (yaml.privacy_step) {
    node[PN_P.privacyStep] = [];

    for (let i = 0; i < yaml.privacy_step.length; i++) {
      let ps = PStepUtils.YAML2Node(yaml.privacy_step[i], props);

      if (PNDataModel.errors.isError(ps)) {
        return ps; // ERROR SO STOP AND RETURN;
      } else {
        node[PN_P.privacyStep].push(ps);
      }
    }
  }

  // verify the node is valid
  let error = model.utils.verify(node, props);
  if (error) {
    return error;
  } else {
    return node;
  }
};

model.utils.verify = function verify(node, props) {
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

  if (!((jsonldUtils.isType(node, PN_T.PrivacyAlgorithm)) &&
        (jsonldUtils.isType(node, PN_T.Metadata)) &&
        (jsonldUtils.isType(node, PN_T.Resource))
      )) {
    return PNDataModel.errors.createTypeError({
      id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
      errMsg: util.format('ERROR type is not [%s, %s, %s] missing in:%j', PN_T.PrivacyAlgorithm, PN_T.Metadata, PN_T.Resource, node),
    });
  }

  // should have an issuer - note this is populated from the JWT
  if (!node[PN_P.issuer]) {
    return PNDataModel.errors.createTypeError({
      id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
      errMsg: util.format('ERROR %s missing from:%j', PN_P.issuer, node),
    });
  }

  // should have a creation time - note this is populated from the JWT
  if (!node[PN_P.creationTime]) {
    return PNDataModel.errors.createTypeError({
      id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
      errMsg: util.format('ERROR %s missing from:%j', PN_P.creationTime, node),
    });
  }

  let psteps;
  if (!node[PN_P.privacyStep]) {
    return PNDataModel.errors.createTypeError({
      id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
      errMsg: util.format('ERROR %s missing from:%j', PN_P.privacyStep, node),
    });
  } else {
    psteps = jsonldUtils.getArray(node, PN_P.privacyStep);
    if (psteps.length !== 1) {
      return PNDataModel.errors.createTypeError({
        id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
        errMsg: util.format('ERROR %s has can only have 1 entry:%j', PN_P.privacyStep, node),
      });
    }

    props.pa = node;
    let invalid = PStepUtils.verify(psteps[0], props);
    if (invalid) {
      return invalid;
    }
  }

  // all ok :)
  return null;
};

module.exports = {
  utils:        model.utils,
};
