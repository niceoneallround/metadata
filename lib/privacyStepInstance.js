/*jslint node: true, vars: true */

const assert = require('assert');
const jsonldUtils = require('jsonld-utils/lib/jldUtils');
const moment = require('moment');
const PActionIUtils = require('./privacyActionInstance').utils;
const PNDataModel = require('data-models/lib/PNDataModel');
const PN_P = PNDataModel.PROPERTY;
const PN_T = PNDataModel.TYPE;
const util = require('util');

/*

A Privacy Step Instance is created from a Privacy Step at Privacy Pipe creation time.
It contains the fixed runtime metadata to obfuscate or de-obfuscate data.

It is created by a Privacy Broker and has the following properties
 @id: a globally unique url
   https://md.pn.id.webshield.io/pstep_instance/(hostname reversed)#<id>
 @type: [pn_t.PrivacyStepInstance]
 pn_p.privacy_pipe: the @id of the privacy pipe that created the instance
 pn_p.privacy_step: the @id of the privacy step created from
 pn_p.node_type: from the step
 pn_p.client: from either step or pipe
 pn_p.next: from either step or pipe
 pn_p.privacy_action_instance: [<Privacy Action Instances>] – based on what is in step.


*/

var model = {};
model.utils = {};

//
// Create a Privacy Step Instance from the passed in params
//
// *psit - the privacy step instance template passed in the privacy pipe
// *pstep - the privacy step
// *pp - privacy pipe
// props
model.utils.create = function create(psit, pstep, pp, props) {
  'use strict';
  assert(psit, 'psit param is missing');
  assert(pstep, 'pstep param is missing');
  assert(pp, 'pp param is missing');
  assert(props.hostname, util.format('props.hostname missing - required to create ids:%j', props));
  assert(props.domainName, util.format('props.domainName missing - required to create ids:%j', props));

  let node = {};

  if (!(jsonldUtils.isType(psit, PN_T.PrivacyStepInstance))) {
    return PNDataModel.errors.createTypeError({
      id: PNDataModel.ids.createErrorId(props.hostname, moment().unix()),
      errMsg: util.format('ERROR type is not [%s] missing in:%j', PN_T.PrivacyStepInstance, psit),
    });
  }

  node['@id'] = psit['@id'];
  node['@type'] = [PN_T.Metadata, PN_T.PrivacyStepInstance];

  // copy constant values that are always copied
  node[PN_P.privacyStep] = pstep['@id'];
  node[PN_P.nodeType] = pstep[PN_P.nodeType];

  // copy variable values that are only passed at runtime
  node[PN_P.privacyPipe] = pp['@id'];

  // set the client, if in the step then fixed, otherwise use one in instance
  // template
  if (pstep[PN_P.client]) {
    if (psit[PN_P.client]) {
      return PNDataModel.errors.createTypeError({
        id: PNDataModel.ids.createErrorId(props.hostname, moment().unix()),
        errMsg: util.format('ERROR privacy step has a client cannot override in instance step%j instance:%j', pstep, psit),
      });
    } else {
      node[PN_P.client] = pstep[PN_P.client];
    }
  } else {
    node[PN_P.client] = psit[PN_P.client];
  }

  // set the next, if in the step then fixed, otherwise use one in instance
  // template
  if (pstep[PN_P.next]) {
    if (psit[PN_P.next]) {
      return PNDataModel.errors.createTypeError({
        id: PNDataModel.ids.createErrorId(props.hostname, moment().unix()),
        errMsg: util.format('ERROR privacy step has a next cannot override in instance step%j instance:%j', pstep, psit),
      });
    } else {
      node[PN_P.next] = pstep[PN_P.next];
    }
  } else {
    node[PN_P.next] = psit[PN_P.next];
  }

  //
  // Iterate over the privacy action instances templates
  // Note hard coded to only handle one at the moment
  //
  node[PN_P.privacyActionInstance] = [];
  if (psit[PN_P.privacyActionInstance]) {

    if (psit[PN_P.privacyActionInstance].length !== 0) {
      // Can only handle one action so check all constsistent
      if ((psit[PN_P.privacyActionInstance].length !== 1) ||
         (pstep[PN_P.privacyAction].length !== 1)) {

        return PNDataModel.errors.createTypeError({
          id: PNDataModel.ids.createErrorId(props.hostname, moment().unix()),
          errMsg: util.format(
            'ERROR privacy step or instance have more than 1 action, or not the same number of actions step%j Instance:%j',
            pstep, psit),
        });
      }

      // have one privacy action and one privacy action instance
      let pait = PActionIUtils.create(
                      psit[PN_P.privacyActionInstance][0],
                      pstep[PN_P.privacyAction][0],
                      pp,
                      props);

      if (PNDataModel.errors.isError(pait)) {
        return pait; // ERROR SO STOP AND RETURN;
      } else {
        node[PN_P.privacyActionInstance].push(pait);
      }

    }
  }

  return node;
};

//
// convert a YAML node into a Privacy Step Instance JSON-LD node.
// NOTE THIS IS JUST A TEMPLATE not the fully created version
// only pass in what can be overridden
//  - id
//  - privacy_step
//  - privacy_action_instance - array of action instances
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
    node['@id'] = PNDataModel.ids.createPrivacyStepInstanceId(props.domainName, yaml.id);
  }

  node['@type'] = [PN_T.PrivacyStepInstance];

  if (yaml.privacy_step) {
    node[PN_P.privacyStep] = yaml.privacy_step;
  }

  // create the privacy action instance templates
  if (yaml.privacy_action_instance) {
    node[PN_P.privacyActionInstance] = [];

    for (let i = 0; i < yaml.privacy_action_instance.length; i++) {
      let pait = PActionIUtils.YAML2Node(yaml.privacy_action_instance[i], props);

      if (PNDataModel.errors.isError(pait)) {
        return pait; // ERROR SO STOP AND RETURN;
      } else {
        node[PN_P.privacyActionInstance].push(pait);
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

  if (!jsonldUtils.isType(node, PN_T.PrivacyStepInstance)) {
    return PNDataModel.errors.createTypeError({
      id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
      errMsg: util.format('ERROR type is not [%s] missing in:%j', PN_T.PrivacyStepInstance, node),
    });
  }

  if (!node[PN_P.privacyStep]) {
    return PNDataModel.errors.createTypeError({
      id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
      errMsg: util.format('ERROR %s missing from:%j', PN_P.privacyStep, node),
    });
  }

  // verify privacy action instance templates
  if (node[PN_P.privacyActionInstance]) {
    for (let i = 0; i < node[PN_P.privacyActionInstance]; i++) {
      let error = PActionIUtils.verifyTemplate(node[PN_P.privacyActionInstance][i], props);
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
