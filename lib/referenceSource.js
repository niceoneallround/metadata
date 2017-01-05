/*jslint node: true, vars: true */

//
// Represents a Reference Source that is a collaboration of an adapter and the
// privacy agent. Hence is not called privacy agent.
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
model.canons = {}; // constructors for canonical versions that can be used for test

/*
Reference source YAML node has the following format - note issuer, creation time
are passed as props

  - id: // the #value part of the @id
    type: ReferenceSource
    description: // optional
    provision_pipe_url: url to post provisions – note this is typically the url of the adapter
    subject_query_url: url to post queries – note this is typically the url of the adapter
    data_model: the @id of the data model it uses
    privacy_algorithm: the @id of the default privacy algorithm that should be used to obfuscate ingested data that
      is being sent to the identity syndicate. Note the algorithm is not associated with data model as a function of the connector,
      may use different ones depending on circumstances.
    obfuscation_service: the @id of the default obfuscation service to be used with privacy algorithms. This is set at pipe
      creation time.


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
    node['@id'] = PNDataModel.ids.createReferenceSourceId(props.domainName, yaml.id);
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

  if (yaml.pndatamodel) {
    node[PN_P.pnDataModel] = yaml.pndatamodel;
  }

  if (yaml.privacy_algorithm) {
    node[PN_P.privacyAlgorithm] = yaml.privacy_algorithm;
  }

  if (yaml.obfuscation_service) {
    node[PN_P.obfuscationService] = yaml.obfuscation_service;
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

  if (!node[PN_P.pnDataModel]) {
    return PNDataModel.errors.createTypeError({
      id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
      errMsg: util.format('ERROR %s missing from:%j', PN_P.pnDataModel, node),
    });
  }

  if (!node[PN_P.privacyAlgorithm]) {
    return PNDataModel.errors.createTypeError({
      id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
      errMsg: util.format('ERROR %s missing from:%j', PN_P.privacyAlgorithm, node),
    });
  }

  if (!node[PN_P.obfuscationService]) {
    return PNDataModel.errors.createTypeError({
      id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
      errMsg: util.format('ERROR %s missing from:%j', PN_P.obfuscationService, node),
    });
  }

  // all ok :)
  return null;
};

//-------------------------
// Canonical Organization can be used for tests
//--------------------------

model.canons.createTestReferenceSource = function createTestReferenceSource(props) {
  'use strict';

  assert(props, 'props param missing');
  assert(props.hostname, util.format('props.hostname is missing:%s', props));
  assert(props.domainName, util.format('props.domainName is missing:%j', props));

  let yaml = {
    id: 'test-rs-1',
    type: 'referencesource',
    description: 'Test Reference Source',
    provision_pipe_url: 'http://fake.test.webshield.io/provision',
    subject_query_url: 'http://fake.test.webshield.io/subject_query',
    pndatamodel: 'https://md.pn.id.webshield.io/pndatamodel/io/webshield/test/rs#rs-subjects', // used in testing so may aswell use
    privacy_algorithm: 'https://md.pn.id.webshield.io/privacy_algorithm/io/webshield/test/rs#rs-test-insecure-key-palg', // used in testing
    obfuscation_service: 'https://md.pn.id.webshield.io/obfuscation_service/io/webshield/test/rs/local#rs-os-test-private-1', // used in testing
  };

  // create a JSONLD node
  let md = model.utils.YAML2Node(yaml,
              { hostname: props.hostname,
                domainName: props.domainName,
                issuer: 'fake.setin.canon', creationTime: '282828', });

  if (PNDataModel.errors.isError(md)) {
    assert(false, util.format('failed to create test PNDataModel:%j', md));
  }

  return md;
};

module.exports = {
  canons:       model.canons,
  utils:        model.utils,
};
