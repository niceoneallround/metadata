/*jslint node: true, vars: true */

/*

Is NOT a resource uses by Reference Source Privacy Agent or a Ingres Prvacy Agent (Data Connector). It describes a PN data model, and how it should be protected.
•	@id: https://md.pn.id.webshield.io/pn_data_model/<reversed_domain_name>#value
    http://md.id.webshield.io/pn_data_model/com/aetna/enrollment_records”
•	@type: pn_t.PNDataModel
•	pn_p.description
•	pn_p.schema_prefix: https://enrollment_records.aetna.com.schema.webshield.io
•	pn_p.json_schema - string holding the json-schema describing the data model
•	pn_p.jsonld_context – string holding the json-ld context
•	pn_p.trust_criteria: the trust criteria protecting the data model. No matter how obfuscate, the data is always protected the same way.

*/

const assert = require('assert');
const BaseSubjectPNDataModel = require('data-models/lib/BaseSubjectPNDataModel');
const jsonldUtils = require('jsonld-utils/lib/jldUtils');
const moment = require('moment');
const PNDataModel = require('data-models/lib/PNDataModel');
const PN_P = PNDataModel.PROPERTY;
const PN_T = PNDataModel.TYPE;
const util = require('util');

let model = {};
model.utils = {};
model.canons = {}; // constructors for canonical versions that can be used for test
model.CONSTANTS = {};

//
// convert a YAML node into PN Data Model JSON-LD node. Does not check
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

  if (yaml.type.toLowerCase() !== 'pndatamodel') {
    return PNDataModel.errors.createTypeError({
      id: PNDataModel.ids.createErrorId(props.hostname, moment().unix()),
      errMsg: util.format('ERROR type is not KMS:%j', yaml),
    });
  }

  // check has id
  if (!yaml.id) {
    return PNDataModel.errors.createTypeError({
      id: PNDataModel.ids.createErrorId(props.hostname, moment().unix()),
      errMsg: util.format('ERROR id missing from YAML format:%j', yaml),
    });
  } else {
    node['@id'] = PNDataModel.ids.createPNDataModelId(props.domainName, yaml.id);
  }

  node['@type'] = [PN_T.Metadata, PN_T.PNDataModel];

  if (yaml.description) {
    node[PN_P.description] = yaml.description;
  }

  if (yaml.json_schema) {
    // this must be string, as it may not be JSONLD compliant and have
    // non URL props, so any expand operation would remove.
    // Check if a string if so then leave otherwise stringify
    if (typeof yaml.json_schema === 'string') {
      node[PN_P.jsonSchema] = yaml.json_schema;
    } else {
      node[PN_P.jsonSchema] = JSON.stringify(yaml.json_schema);
    }
  }

  if (yaml.jsonld_context) {
    // this must be string, as it may not be JSONLD compliant and have
    // non URL props, so any expand operation would remove.
    // Check if a string if so then leave otherwise stringify
    if (typeof yaml.jsonld_context === 'string') {
      node[PN_P.jsonldContext] = yaml.jsonld_context;
    } else {
      node[PN_P.jsonldContext] = JSON.stringify(yaml.jsonld_context);
    }
  }

  if (yaml.schema_prefix) {
    node[PN_P.schemaPrefix] = yaml.schema_prefix;
  }

  if (yaml.trust_criteria) {
    node[PN_P.trustCriteria] = yaml.trust_criteria;
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

model.utils.verify = function verify(node, props) {
  'use strict';

  assert(node, 'node param missing');
  assert(props, 'props param is missing');
  assert(props.hostname, util.format('props.hostname is missing:%j', props));

  let hostname = props.hostname;

  if (!node['@id']) {
    return PNDataModel.errors.createTypeError({
      id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
      errMsg: util.format('ERROR @id missing from:%j', node),
    });
  }

  if (!((jsonldUtils.isType(node, PN_T.PNDataModel)) &&
        (jsonldUtils.isType(node, PN_T.Metadata))
      )) {
    return PNDataModel.errors.createTypeError({
      id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
      errMsg: util.format('ERROR type is not [%s, %s] missing in:%j', PN_T.PNDataModel, PN_T.Metadata, node),
    });
  }

  if (!node[PN_P.jsonSchema]) {
    return PNDataModel.errors.createTypeError({
      id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
      errMsg: util.format('ERROR %s missing from:%j', PN_P.jsonSchema, node),
    });
  }

  if (!node[PN_P.jsonldContext]) {
    return PNDataModel.errors.createTypeError({
      id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
      errMsg: util.format('ERROR %s missing from:%j', PN_P.jsonldContext, node),
    });
  }

  if (!node[PN_P.schemaPrefix]) {
    return PNDataModel.errors.createTypeError({
      id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
      errMsg: util.format('ERROR %s missing from:%j', PN_P.schemaPrefix, node),
    });
  }

  // all ok :)
  return null;
};

//-------------------------
// Canonical PNDataModel  can be used for tests
//--------------------------

model.canons.createTestPNDataModel = function createTestPNDataModel(props) {
  'use strict';

  assert(props, 'props param missing');
  assert(props.hostname, util.format('props.hostname is missing:%s', props));
  assert(props.domainName, util.format('props.domainName is missing:%j', props));

  //
  // Test data model is populated with information that is useful for testing
  //
  let yaml = {
    id: 'enrollment-records',
    type: 'pndatamodel',
    description: 'A valid test PNDataModel',
    json_schema: BaseSubjectPNDataModel.model.JSON_SCHEMA,
    jsonld_context: BaseSubjectPNDataModel.model.JSONLD_CONTEXT,
    schema_prefix: 'https://pn.schema.webshield.io',
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
  CONSTANTS:    model.CONSTANTS,
  utils:        model.utils,
};
