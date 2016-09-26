/*jslint node: true, vars: true */

//
// Contains constructors and verifiers for a Reference Source
//
// Implements
// * verify() - verifies a reference source JSON-LD node
// * YAML2Node() - converts a YAML node to a JSON-LD node
//

const assert = require('assert');
const jsonldUtils = require('jsonld-utils/lib/jldUtils');
const moment = require('moment');
const PNDataModel = require('data-models/lib/PNDataModel');
const PN_P = PNDataModel.PROPERTY;
const PN_T = PNDataModel.TYPE;
const util = require('util');

var model = {};
model.utils = {};

/*
Reference source YAML node has the following format - note issuer, creation time
are passed as props

  - id: // the #value part of the @id
    type: ReferenceSource
    description: // optional
    provision_pipe_url:
    subject_query_url:


The above is passed in a as JSON node
   { id: , type: , description: , provision_pipe_url:, etc}

*/

//
// convert a YAML node into a Reference Source JSON-LD node. Does not check
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

  if (!yaml.type) {
    return PNDataModel.errors.createTypeError({
      id: PNDataModel.ids.createErrorId(props.hostname, moment().unix()),
      errMsg: util.format('ERROR type missing from YAML format cannot create:%j', yaml),
    });
  }

  if (yaml.type.toLowerCase() !== 'referencesource') {
    return PNDataModel.errors.createTypeError({
      id: PNDataModel.ids.createErrorId(props.hostname, moment().unix()),
      errMsg: util.format('ERROR type is not ReferenceSource:%j', yaml),
    });
  }

  // check has id
  if (!yaml.id) {
    return PNDataModel.errors.createTypeError({
      id: PNDataModel.ids.createErrorId(props.hostname, moment().unix()),
      errMsg: util.format('ERROR id missing from YAML format:%j', yaml),
    });
  } else {
    node['@id'] = PNDataModel.ids.createResourceId(props.domainName, yaml.id);
  }

  node['@type'] = [PN_T.Metadata, PN_T.Resource, PN_T.ReferenceSource];

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

  if (yaml.provision_pipe_url) {
    node[PN_P.provisionPipeURL] = PNDataModel.model.utils.createURLValue(yaml.provision_pipe_url);
  }

  if (yaml.subject_query_url) {
    node[PN_P.subjectQueryURL] = PNDataModel.model.utils.createURLValue(yaml.subject_query_url);
  }

  return node;

};

//--------------------------------------
// verifier a Reference Source JSON-LD node and all its sub-nodes
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

  if (!((jsonldUtils.isType(node, PN_T.ReferenceSource)) &&
        (jsonldUtils.isType(node, PN_T.Metadata)) &&
        (jsonldUtils.isType(node, PN_T.Resource))
      )) {
    return PNDataModel.errors.createTypeError({
      id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
      errMsg: util.format('ERROR type is not [%s, %s, %s] missing in:%j', PN_T.ReferenceSource, PN_T.Metadata, PN_T.Resource, node),
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

  if (!node[PN_P.provisionPipeURL]) {
    return PNDataModel.errors.createTypeError({
      id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
      errMsg: util.format('ERROR %s missing from:%j', PN_P.provisionPipeURL, node),
    });
  }

  if (!node[PN_P.subjectQueryURL]) {
    return PNDataModel.errors.createTypeError({
      id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
      errMsg: util.format('ERROR %s missing from:%j', PN_P.subjectQueryURL, node),
    });
  }

  // all ok :)
  return null;
};

module.exports = {
  utils:        model.utils,
};
