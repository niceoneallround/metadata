/*jslint node: true, vars: true */

/*
 A provision contains the metadata that needs to be installed and executed by
 the reciever. Today this is just privacy algorithm instance information.
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
// convert a YAML node into provision SON-LD node. Does not check
// for anything other tha id as ok to have fields missing as can be added from
// other sources, for example issuer, and creation time.
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
  let node = {};

  // check has id
  if (!yaml.id) {
    return PNDataModel.errors.createTypeError({
      id: PNDataModel.ids.createErrorId(props.hostname, moment().unix()),
      errMsg: util.format('ERROR id missing from YAML format:%j', yaml),
    });
  } else {
    node['@id'] = PNDataModel.ids.createProvisionId(props.domainName, yaml.id);
  }

  node['@type'] = [PN_T.Provision];

  // FIXME does not convert any metadata requires it to be passed in as JSONLD-node
  if (yaml.provisioned_metadata) {
    node[PN_P.provisionedMetadata] = yaml.provisioned_metadata;
  }

  if (yaml.privacy_pipe) {
    node[PN_P.privacyPipe] = yaml.privacy_pipe;
  }

  if (yaml.description) {
    node[PN_P.description] = yaml.description;
  }

  // add optional props
  if ((props) && (props.issuer)) {
    node[PN_P.issuer] = props.issuer;
  }

  if ((props) && (props.creationTime)) {
    node[PN_P.creationTime] = props.creationTime;
  }

  return node;

};

//--------------------------------------
// verifier - Does not verify the metadata
//--------------------------------------

model.utils.verify = function verify(node, hostname) {
  'use strict';

  assert(node, 'node param missing');
  assert(hostname, 'hostname param missing');

  if (!node['@id']) {
    return PNDataModel.errors.createTypeError({
      id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
      errMsg: util.format('ERROR @id missing from:%j', node),
    });
  }

  if (!jsonldUtils.isType(node, PN_T.Provision)) {
    return PNDataModel.errors.createTypeError({
      id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
      errMsg: util.format('ERROR type is not [%s] missing in:%j', PN_T.Provision, node),
    });
  }

  if (!node[PN_P.provisionedMetadata]) {
    return PNDataModel.errors.createTypeError({
      id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
      errMsg: util.format('ERROR %s missing from:%j', PN_P.provisionedMetadatar, node),
    });
  }

  if (!node[PN_P.privacyPipe]) {
    return PNDataModel.errors.createTypeError({
      id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
      errMsg: util.format('ERROR %s missing from:%j', PN_P.privacyPipe, node),
    });
  }

  // all ok :)
  return null;
};

module.exports = {
  utils:        model.utils,
};
