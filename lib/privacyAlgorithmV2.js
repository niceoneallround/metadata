/*jslint node: true, vars: true */

//
// Contains constructors and verifiers for privacy algorithms, privacy steps
// and privacy actions.
//
// Implements
// * verify() - verifies a privacy algorithm JSON-LD node
// * YAML2Node() - converts a YAML node to a JSON-LD node
//

//
// THE V2 code does not change the model, just how it is constructed as
// delegates to the step and actions as opposed to having code inline
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
model.canons = {}; // constructors for canonical versions that can be used for test

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
  assert(node, 'verify node param missing');
  assert(props, 'verify props param is missing');
  assert(props.hostname, 'verify props.hostname is missing');

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

//-------------------------
// Canonical Privacy Algorithm can be used for tests
//--------------------------

model.canons.createPrivacyAlgorithm = function createPrivacyAlgorithm(props) {
  'use strict';

  assert(props, 'props param missing');
  assert(props.hostname, util.format('props.hostname is missing:%s', props));
  assert(props.domainName, util.format('props.domainName is missing:%j', props));

  let yaml = {
    id: '23',
    type: 'privacyalgorithm',
    description: 'A valid PA that shows all the mandatory fields, except this one',
    privacy_step: [{
      id: 'pstep-1',
      description: 'a test privacy step',
      node_type: 'connector',
      privacy_action: [{
        id: 'paction-1',
        description: 'canon action created from privacy algorithmv2 metadata',
        content_obfuscation_algorithm: 'A256GCM',
        content_encrypt_key_md: 'https://md.pn.id.webshield.io/encrypt_key_md/com/fake#content-key-1', // Test EKMD does not have to exist as nock out call
        obfuscation_provider: 'http://ionicsecurity.com',
        kms: 'https://md.pn.id.webshield.io/kms/com/fake#kms-1', // the canon Test KMS does not have to exist as nock out call
        skip_orchestration: false,
        schema:  {
          $schema: 'http://experian.schema.webshield.io',
          'http//json-schema.org/title': 'http://experian.schema.webshield.io/type#Subject',
          'http://json-schema.org/type': 'object', },
      },
    ],
    },
    ],
  };

  // create a JSONLD node
  let md = model.utils.YAML2Node(yaml,
              { hostname: props.hostname,
                domainName: props.domainName,
                issuer: 'fake.setin.canon', creationTime: '282828', });

  if (PNDataModel.errors.isError(md)) {
    assert(false, util.format('failed to create privacy algorithm:%j', md));
  }

  return md;
};

module.exports = {
  utils:  model.utils,
  canons: model.canons,
};
