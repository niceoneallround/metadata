/*jslint node: true, vars: true */

const assert = require('assert');
const jsonldUtils = require('jsonld-utils/lib/jldUtils');
const moment = require('moment');
const PStepIUtils = require('./privacyStepInstance').utils;
const PNDataModel = require('data-models/lib/PNDataModel');
const PN_P = PNDataModel.PROPERTY;
const PN_T = PNDataModel.TYPE;
const util = require('util');

/*

A Privacy Algorithm Instance is created from a Privacy Algorithm at Privacy Pipe creation time,
and it contains the constant and runtime information.

It has the following properties
•	@id: a globally unique url
   https://md.pn.id.webshield.io/pstep_instance/(hostname reversed)#<id>
•	@type: [pn_t.PrivacyAlgorithmInstance]
•	pn_p.privacy_pipe: the @id of the privacy pipe that created the instance
•	pn_p.privacy_algorithm: the @id of the privacy algorithm
•	pn_p.privacy_step_instance: [<Privacy Step Instances>]

*/

var model = {};
model.utils = {};

//
// Create a Privacy Algorithm Instance from the passed in params
//
// *palgit - the privacy algorithm instance template passed in the privacy pipe
// *pstep - the privacy algorithm
// *pp - privacy pipe
// props
model.utils.create = function create(palgit, palg, pp, props) {
  'use strict';
  assert(palgit, 'palgit param is missing');
  assert(palg, 'palg param is missing');
  assert(pp, 'pp param is missing');
  assert(props.hostname, util.format('props.hostname missing - required to create ids:%j', props));
  assert(props.domainName, util.format('props.domainName missing - required to create ids:%j', props));

  let node = {};

  if (!(jsonldUtils.isType(palgit, PN_T.PrivacyAlgorithmInstance))) {
    return PNDataModel.errors.createTypeError({
      id: PNDataModel.ids.createErrorId(props.hostname, moment().unix()),
      errMsg: util.format('ERROR type is not [%s] missing in:%j', PN_T.PrivacyAlgorithmInstance, palgit),
    });
  }

  node['@id'] = palgit['@id'];
  node['@type'] = [PN_T.Metadata, PN_T.PrivacyAlgorithmInstance];

  // copy constant values that are always copied
  node[PN_P.privacyAlgorithm] = palg['@id'];

  // copy variable values that are only passed at runtime
  node[PN_P.privacyPipe] = pp['@id'];

  //
  // Iterate over the privacy step instances templates
  //
  node[PN_P.privacyStepInstance] = [];
  if (palgit[PN_P.privacyStepInstance]) {

    if (palgit[PN_P.privacyStepInstance].length !== 0) {
      // Can only handle one step so check all constsistent
      if ((palgit[PN_P.privacyStepInstance].length !== 1) ||
         (palg[PN_P.privacyStep].length !== 1)) {

        return PNDataModel.errors.createTypeError({
          id: PNDataModel.ids.createErrorId(props.hostname, moment().unix()),
          errMsg: util.format(
            'ERROR privacy alg or instance have more than 1 step, or not the same number of steps alg%j Instance:%j',
            palg, palgit),
        });
      }

      // have one privacy action and one privacy action instance
      let psit = PStepIUtils.create(
                      palgit[PN_P.privacyStepInstance][0],
                      palg[PN_P.privacyStep][0],
                      pp,
                      props);

      if (PNDataModel.errors.isError(psit)) {
        return psit; // ERROR SO STOP AND RETURN;
      } else {
        node[PN_P.privacyStepInstance].push(psit);
      }
    }
  }

  return node;
};

//
// convert a YAML node into a Privacy Algorithm Instance JSON-LD node.
// NOTE THIS IS JUST A TEMPLATE not the fully created version
// only pass in what can be overridden or needed to start process
//  - id
//  - description
//  - privacy_algorithm - the id
//  - privacy_step_instance
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
    node['@id'] = PNDataModel.ids.createPrivacyAlgorithmInstanceId(props.domainName, yaml.id);
  }

  node['@type'] = [PN_T.PrivacyAlgorithmInstance];

  if (yaml.description) {
    node[PN_P.description] = yaml.description;
  }

  if (yaml.privacy_algorithm) {
    node[PN_P.privacyAlgorithm] = yaml.privacy_algorithm;
  }

  // create the privacy action instance templates
  if (yaml.privacy_step_instance) {
    node[PN_P.privacyStepInstance] = [];

    for (let i = 0; i < yaml.privacy_step_instance.length; i++) {
      let psit = PStepIUtils.YAML2Node(yaml.privacy_step_instance[i], props);

      if (PNDataModel.errors.isError(psit)) {
        return psit; // ERROR SO STOP AND RETURN;
      } else {
        node[PN_P.privacyStepInstance].push(psit);
      }
    }
  }

  // verify the node is valid
  let error = model.utils.verifyTemplate(node, props);
  if (error) {
    return error;
  } else {
    return node;
  }
};

// ONLY VERFIY TEMPLATE not fully created
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

  if (!jsonldUtils.isType(node, PN_T.PrivacyAlgorithmInstance)) {
    return PNDataModel.errors.createTypeError({
      id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
      errMsg: util.format('ERROR type is not [%s] missing in:%j', PN_T.PrivacyAlgorithmInstance, node),
    });
  }

  if (!node[PN_P.privacyAlgorithm]) {
    return PNDataModel.errors.createTypeError({
      id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
      errMsg: util.format('ERROR %s missing from:%j', PN_P.privacyAlgorithm, node),
    });
  }

  // verify privacy action instance templates
  if (node[PN_P.privacyStepInstance]) {
    for (let i = 0; i < node[PN_P.privacyStepInstance]; i++) {
      let error = PStepIUtils.verifyTemplate(node[PN_P.privacyStepInstance][i], props);
      if (error) {
        return error;
      }
    }
  }

  // all ok :)
  return null;
};

module.exports = {
  utils:        model.utils,
};
